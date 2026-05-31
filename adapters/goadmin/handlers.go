package goadmin

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	router "github.com/goliatone/go-router"
)

// BrowserFlow is the OIDC browser orchestration boundary used by HTTP handlers.
type BrowserFlow interface {
	BeginLogin(context.Context, oidc.AuthorizationRequest) (oidc.AuthorizationResponse, error)
	CompleteCallback(context.Context, oidc.CallbackRequest) (oidc.BrowserSessionResult, error)
}

// CookieAuthenticator is satisfied by *auth.RouteAuthenticator.
type CookieAuthenticator interface {
	SetAuthCookie(router.Context, string, ...auth.AuthCookieOption) error
	Logout(router.Context)
}

// ActivityRecorder is satisfied by auth.ActivitySink.
type ActivityRecorder interface {
	Record(context.Context, auth.ActivityEvent) error
}

// ManualLinker optionally handles protected account-link requests.
type ManualLinker interface {
	Link(ctx context.Context, userID string, providerKey string, subject string) error
}

// ManualUnlinker optionally handles protected account-unlink requests.
type ManualUnlinker interface {
	Unlink(ctx context.Context, userID string, providerKey string, subject string) error
}

// ManualLinkProof captures a verified provider-subject link target.
type ManualLinkProof struct {
	ProviderKey string
	Subject     string
	Metadata    map[string]any
}

// ManualLinkProofVerifier verifies that the current request may link the
// provider subject before ManualLinker persists it.
type ManualLinkProofVerifier interface {
	VerifyManualLink(ctx context.Context, userID string, providerKey string, subject string) (ManualLinkProof, error)
}

// LogoutRedirectResolver returns an optional IdP logout redirect target.
type LogoutRedirectResolver func(providerKey string) string

// HandlerConfig wires concrete dependencies for SSO browser handlers.
type HandlerConfig struct {
	Providers              []oidc.ProviderInfo
	Browser                BrowserFlow
	RouteAuthenticator     CookieAuthenticator
	ActivitySink           ActivityRecorder
	ManualLinker           ManualLinker
	ManualLinkVerifier     ManualLinkProofVerifier
	ManualUnlinker         ManualUnlinker
	LogoutRedirect         LogoutRedirectResolver
	DefaultLogoutRedirect  string
	ExtendedSessionCookies bool
}

// NewHandlers builds production SSO route handlers.
func NewHandlers(cfg HandlerConfig) (Handlers, error) {
	if cfg.Browser == nil {
		return Handlers{}, fmt.Errorf("go-auth sso browser authenticator is required")
	}
	if cfg.RouteAuthenticator == nil {
		return Handlers{}, fmt.Errorf("go-auth route authenticator is required")
	}
	if cfg.ManualLinker != nil && cfg.ManualLinkVerifier == nil {
		return Handlers{}, fmt.Errorf("go-auth manual link proof verifier is required when manual linker is configured")
	}
	runtime := handlerRuntime{
		providers:             sanitizeProviderInfo(cfg.Providers),
		browser:               cfg.Browser,
		routeAuth:             cfg.RouteAuthenticator,
		activitySink:          cfg.ActivitySink,
		manualLinker:          cfg.ManualLinker,
		manualLinkVerifier:    cfg.ManualLinkVerifier,
		manualUnlinker:        cfg.ManualUnlinker,
		logoutRedirect:        cfg.LogoutRedirect,
		defaultLogoutRedirect: cfg.DefaultLogoutRedirect,
		extendedCookies:       cfg.ExtendedSessionCookies,
	}
	if strings.TrimSpace(runtime.defaultLogoutRedirect) == "" {
		runtime.defaultLogoutRedirect = "/"
	}
	return Handlers{
		ProviderList: runtime.providerList,
		BeginLogin:   runtime.beginLogin,
		Callback:     runtime.callback,
		Link:         runtime.link,
		Unlink:       runtime.unlink,
		Logout:       runtime.logout,
	}, nil
}

type handlerRuntime struct {
	providers             []oidc.ProviderInfo
	browser               BrowserFlow
	routeAuth             CookieAuthenticator
	activitySink          ActivityRecorder
	manualLinker          ManualLinker
	manualLinkVerifier    ManualLinkProofVerifier
	manualUnlinker        ManualUnlinker
	logoutRedirect        LogoutRedirectResolver
	defaultLogoutRedirect string
	extendedCookies       bool
}

func (h handlerRuntime) providerList(c router.Context) error {
	return c.JSON(http.StatusOK, map[string]any{"providers": h.providers})
}

func (h handlerRuntime) beginLogin(c router.Context) error {
	providerKey := providerKeyFromContext(c)
	res, err := h.browser.BeginLogin(c.Context(), oidc.AuthorizationRequest{
		ProviderKey: providerKey,
		RedirectTo:  c.Query("redirect_to"),
		LoginHint:   c.Query("login_hint"),
	})
	if err != nil {
		h.record(c.Context(), auth.ActivityEventSSOLoginFailure, "", map[string]any{
			"provider": providerKey,
			"stage":    "begin",
			"error":    err.Error(),
		})
		return safeHandlerError(c, http.StatusBadRequest, "sso login could not start")
	}
	return c.Redirect(res.RedirectURL, http.StatusFound)
}

func (h handlerRuntime) callback(c router.Context) error {
	providerKey := providerKeyFromContext(c)
	result, err := h.browser.CompleteCallback(c.Context(), oidc.CallbackRequest{
		ProviderKey: providerKey,
		Code:        c.Query("code"),
		State:       c.Query("state"),
		RedirectTo:  c.Query("redirect_to"),
	})
	if err != nil {
		h.record(c.Context(), auth.ActivityEventSSOLoginFailure, "", map[string]any{
			"provider": providerKey,
			"stage":    "callback",
			"error":    err.Error(),
		})
		return safeHandlerError(c, http.StatusUnauthorized, "sso login failed")
	}

	cookieOpts := []auth.AuthCookieOption(nil)
	if h.extendedCookies {
		cookieOpts = append(cookieOpts, auth.WithExtendedAuthCookieDuration())
	}
	if err := h.routeAuth.SetAuthCookie(c, result.LocalToken, cookieOpts...); err != nil {
		h.record(c.Context(), auth.ActivityEventSSOLoginFailure, result.Audit.UserID, map[string]any{
			"provider": result.ProviderKey,
			"stage":    "cookie",
			"error":    err.Error(),
		})
		return safeHandlerError(c, http.StatusInternalServerError, "sso session could not be created")
	}

	metadata := cloneMap(result.Audit.Metadata)
	metadata["provider"] = result.ProviderKey
	h.record(c.Context(), auth.ActivityEventSSOLoginSuccess, result.Audit.UserID, metadata)

	target := strings.TrimSpace(result.RedirectTarget)
	if target == "" {
		target = "/"
	}
	return c.Redirect(target, http.StatusFound)
}

func (h handlerRuntime) link(c router.Context) error {
	if h.manualLinker == nil {
		return safeHandlerError(c, http.StatusNotImplemented, "sso account linking is not configured")
	}
	userID := userIDFromContext(c.Context())
	if userID == "" {
		return safeHandlerError(c, http.StatusUnauthorized, "authenticated user is required")
	}
	providerKey := providerKeyFromContext(c)
	subject := strings.TrimSpace(c.FormValue("subject", c.Query("subject")))
	if subject == "" {
		return safeHandlerError(c, http.StatusBadRequest, "subject is required")
	}
	proof, err := h.manualLinkVerifier.VerifyManualLink(c.Context(), userID, providerKey, subject)
	if err != nil {
		h.record(c.Context(), auth.ActivityEventSSOLinkRejected, userID, map[string]any{
			"provider": providerKey,
			"stage":    "verify",
			"error":    err.Error(),
		})
		return safeHandlerError(c, http.StatusForbidden, "sso account link failed")
	}
	verifiedProvider := strings.TrimSpace(proof.ProviderKey)
	if verifiedProvider == "" || !strings.EqualFold(verifiedProvider, providerKey) {
		h.record(c.Context(), auth.ActivityEventSSOLinkRejected, userID, map[string]any{
			"provider": providerKey,
			"stage":    "verify",
			"error":    "verified provider mismatch",
		})
		return safeHandlerError(c, http.StatusForbidden, "sso account link failed")
	}
	verifiedSubject := strings.TrimSpace(proof.Subject)
	if verifiedSubject == "" || verifiedSubject != subject {
		h.record(c.Context(), auth.ActivityEventSSOLinkRejected, userID, map[string]any{
			"provider": providerKey,
			"stage":    "verify",
			"error":    "verified subject mismatch",
		})
		return safeHandlerError(c, http.StatusForbidden, "sso account link failed")
	}
	if err := h.manualLinker.Link(c.Context(), userID, verifiedProvider, verifiedSubject); err != nil {
		h.record(c.Context(), auth.ActivityEventSSOLinkRejected, userID, map[string]any{
			"provider": verifiedProvider,
			"error":    err.Error(),
		})
		return safeHandlerError(c, http.StatusForbidden, "sso account link failed")
	}
	metadata := cloneMap(proof.Metadata)
	metadata["provider"] = verifiedProvider
	metadata["subject"] = verifiedSubject
	metadata["verified"] = true
	h.record(c.Context(), auth.ActivityEventSSOLinkManual, userID, metadata)
	return c.NoContent(http.StatusNoContent)
}

func (h handlerRuntime) unlink(c router.Context) error {
	if h.manualUnlinker == nil {
		return safeHandlerError(c, http.StatusNotImplemented, "sso account unlinking is not configured")
	}
	userID := userIDFromContext(c.Context())
	if userID == "" {
		return safeHandlerError(c, http.StatusUnauthorized, "authenticated user is required")
	}
	providerKey := providerKeyFromContext(c)
	subject := strings.TrimSpace(c.FormValue("subject", c.Query("subject")))
	if subject == "" {
		return safeHandlerError(c, http.StatusBadRequest, "subject is required")
	}
	if err := h.manualUnlinker.Unlink(c.Context(), userID, providerKey, subject); err != nil {
		h.record(c.Context(), auth.ActivityEventSSOLinkRejected, userID, map[string]any{
			"provider": providerKey,
			"stage":    "unlink",
			"error":    err.Error(),
		})
		return safeHandlerError(c, http.StatusForbidden, "sso account unlink failed")
	}
	h.record(c.Context(), auth.ActivityEventSSOUnlink, userID, map[string]any{
		"provider": providerKey,
		"subject":  subject,
	})
	return c.NoContent(http.StatusNoContent)
}

func (h handlerRuntime) logout(c router.Context) error {
	providerKey := providerKeyFromContext(c)
	userID := userIDFromContext(c.Context())
	h.routeAuth.Logout(c)
	h.record(c.Context(), auth.ActivityEventSSOLogout, userID, map[string]any{
		"provider": providerKey,
	})
	target := h.defaultLogoutRedirect
	if h.logoutRedirect != nil {
		if resolved := strings.TrimSpace(h.logoutRedirect(providerKey)); resolved != "" {
			target = resolved
		}
	}
	return c.Redirect(target, http.StatusFound)
}

func providerKeyFromContext(c router.Context) string {
	if c == nil {
		return ""
	}
	if key := strings.TrimSpace(c.Param("provider")); key != "" {
		return key
	}
	return strings.TrimSpace(c.Query("provider"))
}

func userIDFromContext(ctx context.Context) string {
	claims, ok := auth.GetClaims(ctx)
	if !ok || claims == nil {
		return ""
	}
	return strings.TrimSpace(claims.UserID())
}

func sanitizeProviderInfo(providers []oidc.ProviderInfo) []oidc.ProviderInfo {
	out := make([]oidc.ProviderInfo, 0, len(providers))
	seen := map[string]struct{}{}
	for _, provider := range providers {
		key := strings.TrimSpace(provider.Key)
		if key == "" {
			continue
		}
		normalized := strings.ToLower(key)
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, oidc.ProviderInfo{
			Key:            key,
			Label:          strings.TrimSpace(provider.Label),
			LoginURL:       strings.TrimSpace(provider.LoginURL),
			Icon:           strings.TrimSpace(provider.Icon),
			IconURL:        strings.TrimSpace(provider.IconURL),
			DisabledReason: strings.TrimSpace(provider.DisabledReason),
		})
	}
	return out
}

func safeHandlerError(c router.Context, status int, message string) error {
	return c.JSON(status, map[string]string{"error": message})
}

func (h handlerRuntime) record(ctx context.Context, eventType auth.ActivityEventType, userID string, metadata map[string]any) {
	if h.activitySink == nil {
		return
	}
	_ = h.activitySink.Record(ctx, auth.ActivityEvent{
		EventType: eventType,
		Actor:     auth.ActorRef{ID: userID, Type: "user"},
		UserID:    userID,
		Metadata:  metadata,
	})
}

func cloneMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
