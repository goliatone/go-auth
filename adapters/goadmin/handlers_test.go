package goadmin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	router "github.com/goliatone/go-router"
	"github.com/stretchr/testify/mock"
)

func TestProviderListReturnsOnlyDisplayData(t *testing.T) {
	handlers, err := NewHandlers(HandlerConfig{
		Providers: []oidc.ProviderInfo{
			{Key: "auth0", Label: "Auth0", LoginURL: "/admin/sso/login/auth0", Icon: "lock", DisabledReason: "maintenance"},
		},
		Browser:            stubBrowserFlow{},
		RouteAuthenticator: &spyCookieAuthenticator{},
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	c := router.NewMockContext()
	c.On("JSON", http.StatusOK, mock.MatchedBy(func(payload any) bool {
		body, ok := payload.(map[string]any)
		if !ok {
			return false
		}
		providers, ok := body["providers"].([]oidc.ProviderInfo)
		return ok &&
			len(providers) == 1 &&
			providers[0].Key == "auth0" &&
			providers[0].LoginURL == "/admin/sso/login/auth0"
	})).Return(nil)

	if err := handlers.ProviderList(c); err != nil {
		t.Fatalf("ProviderList: %v", err)
	}
	c.AssertExpectations(t)
}

func TestBeginLoginRedirectsToOIDCAuthorizationURL(t *testing.T) {
	browser := stubBrowserFlow{
		begin: func(ctx context.Context, req oidc.AuthorizationRequest) (oidc.AuthorizationResponse, error) {
			if req.ProviderKey != "auth0" || req.RedirectTo != "/admin" || req.LoginHint != "admin@example.com" {
				t.Fatalf("unexpected request: %#v", req)
			}
			return oidc.AuthorizationResponse{RedirectURL: "https://idp.example/authorize"}, nil
		},
	}
	handlers, err := NewHandlers(HandlerConfig{Browser: browser, RouteAuthenticator: &spyCookieAuthenticator{}})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	c := router.NewMockContext()
	c.ParamsM["provider"] = "auth0"
	c.QueriesM["redirect_to"] = "/admin"
	c.QueriesM["login_hint"] = "admin@example.com"
	c.On("Context").Return(context.Background())
	c.On("Redirect", "https://idp.example/authorize", []int{http.StatusFound}).Return(nil)

	if err := handlers.BeginLogin(c); err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	c.AssertExpectations(t)
}

func TestCallbackSetsCookieThroughRouteAuthenticator(t *testing.T) {
	cookieAuth := &spyCookieAuthenticator{}
	activity := &recordingActivitySink{}
	browser := stubBrowserFlow{
		callback: func(ctx context.Context, req oidc.CallbackRequest) (oidc.BrowserSessionResult, error) {
			if req.ProviderKey != "auth0" || req.Code != "code" || req.State != "state" {
				t.Fatalf("unexpected callback request: %#v", req)
			}
			return oidc.BrowserSessionResult{
				LocalToken:     "local-jwt",
				ProviderKey:    "auth0",
				RedirectTarget: "/admin",
				Audit: oidc.AuditMetadata{
					UserID:   "user-1",
					Metadata: map[string]any{"subject": "sub-1"},
				},
			}, nil
		},
	}
	handlers, err := NewHandlers(HandlerConfig{Browser: browser, RouteAuthenticator: cookieAuth, ActivitySink: activity})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	c := router.NewMockContext()
	c.ParamsM["provider"] = "auth0"
	c.QueriesM["code"] = "code"
	c.QueriesM["state"] = "state"
	c.On("Context").Return(context.Background())
	c.On("Redirect", "/admin", []int{http.StatusFound}).Return(nil)

	if err := handlers.Callback(c); err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if cookieAuth.token != "local-jwt" {
		t.Fatalf("SetAuthCookie token = %q", cookieAuth.token)
	}
	if len(activity.events) != 1 || activity.events[0].EventType != auth.ActivityEventSSOLoginSuccess {
		t.Fatalf("expected login success activity, got %#v", activity.events)
	}
	c.AssertExpectations(t)
}

func TestCallbackRecordsSafeFailureWithoutCookie(t *testing.T) {
	cookieAuth := &spyCookieAuthenticator{}
	activity := &recordingActivitySink{}
	handlers, err := NewHandlers(HandlerConfig{
		Browser: stubBrowserFlow{
			callback: func(context.Context, oidc.CallbackRequest) (oidc.BrowserSessionResult, error) {
				return oidc.BrowserSessionResult{}, errors.New("invalid id token with sensitive details")
			},
		},
		RouteAuthenticator: cookieAuth,
		ActivitySink:       activity,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	c := router.NewMockContext()
	c.ParamsM["provider"] = "auth0"
	c.On("Context").Return(context.Background())
	c.On("JSON", http.StatusUnauthorized, map[string]string{"error": "sso login failed"}).Return(nil)

	if err := handlers.Callback(c); err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if cookieAuth.token != "" {
		t.Fatalf("did not expect SetAuthCookie, got token %q", cookieAuth.token)
	}
	if len(activity.events) != 1 || activity.events[0].EventType != auth.ActivityEventSSOLoginFailure {
		t.Fatalf("expected login failure activity, got %#v", activity.events)
	}
	if strings.Contains(fmt.Sprint(activity.events[0].Metadata), "sensitive details") {
		t.Fatalf("activity metadata leaked callback error: %#v", activity.events[0].Metadata)
	}
	c.AssertExpectations(t)
}

func TestProtectedLinkRequiresSessionClaimsAndCallsManualLinker(t *testing.T) {
	linker := &spyManualLinker{}
	verifier := &spyManualLinkVerifier{proof: ManualLinkProof{
		ProviderKey: "auth0",
		Subject:     "sub-1",
		Metadata:    map[string]any{"method": "callback"},
	}}
	handlers, err := NewHandlers(HandlerConfig{
		Browser:            stubBrowserFlow{},
		RouteAuthenticator: &spyCookieAuthenticator{},
		ManualLinker:       linker,
		ManualLinkVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	ctx := auth.WithClaimsContext(context.Background(), &auth.JWTClaims{UID: "user-1"})
	c := router.NewMockContext()
	c.ParamsM["provider"] = "auth0"
	c.QueriesM["subject"] = "sub-1"
	c.On("Context").Return(ctx)
	c.On("FormValue", "subject", "sub-1").Return("sub-1")
	c.On("NoContent", http.StatusNoContent).Return(nil)

	if err := handlers.Link(c); err != nil {
		t.Fatalf("Link: %v", err)
	}
	if verifier.userID != "user-1" || verifier.provider != "auth0" || verifier.subject != "sub-1" {
		t.Fatalf("unexpected verifier call: %#v", verifier)
	}
	if linker.userID != "user-1" || linker.provider != "auth0" || linker.subject != "sub-1" {
		t.Fatalf("unexpected link call: %#v", linker)
	}
	c.AssertExpectations(t)
}

func TestNewHandlersRejectsManualLinkerWithoutVerifier(t *testing.T) {
	_, err := NewHandlers(HandlerConfig{
		Browser:            stubBrowserFlow{},
		RouteAuthenticator: &spyCookieAuthenticator{},
		ManualLinker:       &spyManualLinker{},
	})
	if err == nil || !strings.Contains(err.Error(), "proof verifier") {
		t.Fatalf("expected proof verifier error, got %v", err)
	}
}

func TestProtectedLinkRejectsUnverifiedSubject(t *testing.T) {
	linker := &spyManualLinker{}
	verifier := &spyManualLinkVerifier{err: errors.New("subject proof failed")}
	handlers, err := NewHandlers(HandlerConfig{
		Browser:            stubBrowserFlow{},
		RouteAuthenticator: &spyCookieAuthenticator{},
		ManualLinker:       linker,
		ManualLinkVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	ctx := auth.WithClaimsContext(context.Background(), &auth.JWTClaims{UID: "user-1"})
	c := router.NewMockContext()
	c.ParamsM["provider"] = "auth0"
	c.QueriesM["subject"] = "sub-1"
	c.On("Context").Return(ctx)
	c.On("FormValue", "subject", "sub-1").Return("sub-1")
	c.On("JSON", http.StatusForbidden, map[string]string{"error": "sso account link failed"}).Return(nil)

	if err := handlers.Link(c); err != nil {
		t.Fatalf("Link: %v", err)
	}
	if linker.userID != "" || linker.provider != "" || linker.subject != "" {
		t.Fatalf("did not expect link call: %#v", linker)
	}
	c.AssertExpectations(t)
}

func TestProtectedLinkRejectsMismatchedProof(t *testing.T) {
	linker := &spyManualLinker{}
	verifier := &spyManualLinkVerifier{proof: ManualLinkProof{
		ProviderKey: "okta",
		Subject:     "sub-1",
	}}
	handlers, err := NewHandlers(HandlerConfig{
		Browser:            stubBrowserFlow{},
		RouteAuthenticator: &spyCookieAuthenticator{},
		ManualLinker:       linker,
		ManualLinkVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	ctx := auth.WithClaimsContext(context.Background(), &auth.JWTClaims{UID: "user-1"})
	c := router.NewMockContext()
	c.ParamsM["provider"] = "auth0"
	c.QueriesM["subject"] = "sub-1"
	c.On("Context").Return(ctx)
	c.On("FormValue", "subject", "sub-1").Return("sub-1")
	c.On("JSON", http.StatusForbidden, map[string]string{"error": "sso account link failed"}).Return(nil)

	if err := handlers.Link(c); err != nil {
		t.Fatalf("Link: %v", err)
	}
	if linker.userID != "" || linker.provider != "" || linker.subject != "" {
		t.Fatalf("did not expect link call: %#v", linker)
	}
	c.AssertExpectations(t)
}

func TestProtectedUnlinkRequiresSessionClaimsAndCallsManualUnlinker(t *testing.T) {
	unlinker := &spyManualUnlinker{}
	activity := &recordingActivitySink{}
	handlers, err := NewHandlers(HandlerConfig{
		Browser:            stubBrowserFlow{},
		RouteAuthenticator: &spyCookieAuthenticator{},
		ManualUnlinker:     unlinker,
		ActivitySink:       activity,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	ctx := auth.WithClaimsContext(context.Background(), &auth.JWTClaims{UID: "user-1"})
	c := router.NewMockContext()
	c.ParamsM["provider"] = "auth0"
	c.QueriesM["subject"] = "sub-1"
	c.On("Context").Return(ctx)
	c.On("FormValue", "subject", "sub-1").Return("sub-1")
	c.On("NoContent", http.StatusNoContent).Return(nil)

	if err := handlers.Unlink(c); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
	if unlinker.userID != "user-1" || unlinker.provider != "auth0" || unlinker.subject != "sub-1" {
		t.Fatalf("unexpected unlink call: %#v", unlinker)
	}
	if len(activity.events) != 1 || activity.events[0].EventType != auth.ActivityEventSSOUnlink {
		t.Fatalf("expected unlink activity, got %#v", activity.events)
	}
	c.AssertExpectations(t)
}

func TestLogoutClearsLocalCookieAndRedirects(t *testing.T) {
	cookieAuth := &spyCookieAuthenticator{}
	handlers, err := NewHandlers(HandlerConfig{
		Browser:            stubBrowserFlow{},
		RouteAuthenticator: cookieAuth,
		LogoutRedirect: func(providerKey string) string {
			if providerKey != "auth0" {
				t.Fatalf("provider = %q", providerKey)
			}
			return "https://idp.example/logout"
		},
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	c := router.NewMockContext()
	c.ParamsM["provider"] = "auth0"
	c.On("Context").Return(context.Background())
	c.On("Redirect", "https://idp.example/logout", []int{http.StatusFound}).Return(nil)

	if err := handlers.Logout(c); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if !cookieAuth.loggedOut {
		t.Fatal("expected route authenticator logout")
	}
	c.AssertExpectations(t)
}

type stubBrowserFlow struct {
	begin    func(context.Context, oidc.AuthorizationRequest) (oidc.AuthorizationResponse, error)
	callback func(context.Context, oidc.CallbackRequest) (oidc.BrowserSessionResult, error)
}

func (s stubBrowserFlow) BeginLogin(ctx context.Context, req oidc.AuthorizationRequest) (oidc.AuthorizationResponse, error) {
	if s.begin == nil {
		return oidc.AuthorizationResponse{}, nil
	}
	return s.begin(ctx, req)
}

func (s stubBrowserFlow) CompleteCallback(ctx context.Context, req oidc.CallbackRequest) (oidc.BrowserSessionResult, error) {
	if s.callback == nil {
		return oidc.BrowserSessionResult{}, nil
	}
	return s.callback(ctx, req)
}

type spyCookieAuthenticator struct {
	token     string
	loggedOut bool
}

func (s *spyCookieAuthenticator) SetAuthCookie(_ router.Context, token string, _ ...auth.AuthCookieOption) error {
	s.token = token
	return nil
}

func (s *spyCookieAuthenticator) Logout(router.Context) {
	s.loggedOut = true
}

type recordingActivitySink struct {
	events []auth.ActivityEvent
}

func (s *recordingActivitySink) Record(_ context.Context, event auth.ActivityEvent) error {
	s.events = append(s.events, event)
	return nil
}

type spyManualLinker struct {
	userID   string
	provider string
	subject  string
}

func (s *spyManualLinker) Link(_ context.Context, userID string, providerKey string, subject string) error {
	s.userID = userID
	s.provider = providerKey
	s.subject = subject
	return nil
}

type spyManualUnlinker struct {
	userID   string
	provider string
	subject  string
}

func (s *spyManualUnlinker) Unlink(_ context.Context, userID string, providerKey string, subject string) error {
	s.userID = userID
	s.provider = providerKey
	s.subject = subject
	return nil
}

type spyManualLinkVerifier struct {
	userID   string
	provider string
	subject  string
	proof    ManualLinkProof
	err      error
}

func (s *spyManualLinkVerifier) VerifyManualLink(_ context.Context, userID string, providerKey string, subject string) (ManualLinkProof, error) {
	s.userID = userID
	s.provider = providerKey
	s.subject = subject
	if s.err != nil {
		return ManualLinkProof{}, s.err
	}
	return s.proof, nil
}
