package social

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-router"
)

// RouteRegistrar captures the router methods used by the controller.
type RouteRegistrar interface {
	Get(path string, handler router.HandlerFunc, mw ...router.MiddlewareFunc) router.RouteInfo
	Post(path string, handler router.HandlerFunc, mw ...router.MiddlewareFunc) router.RouteInfo
	Delete(path string, handler router.HandlerFunc, mw ...router.MiddlewareFunc) router.RouteInfo
}

// HTTPController handles social auth HTTP routes.
type HTTPController struct {
	authenticator *SocialAuthenticator
	config        HTTPConfig
}

// HTTPConfig configures the HTTP controller.
type HTTPConfig struct {
	// PathPrefix for routes (default: "/auth/social")
	PathPrefix string

	// SessionContextKey is the router locals key used by go-auth (default: "user")
	SessionContextKey string

	// CookieName for storing the JWT (default: SessionContextKey)
	CookieName string

	// CookieSecure sets the Secure flag on cookies
	CookieSecure bool

	// CookieHTTPOnly sets the HttpOnly flag on cookies
	CookieHTTPOnly bool

	// CookieSameSite sets the SameSite attribute (e.g. "Lax", "Strict", "None")
	CookieSameSite string

	// SuccessRedirect is the default redirect after successful auth
	SuccessRedirect string

	// ErrorRedirect is the redirect for auth errors
	ErrorRedirect string

	// ErrorHandler handles errors (optional)
	ErrorHandler func(ctx router.Context, err error) error
}

// NewHTTPController creates a new social auth HTTP controller.
func NewHTTPController(auth *SocialAuthenticator, cfg HTTPConfig) *HTTPController {
	if cfg.PathPrefix == "" {
		cfg.PathPrefix = "/auth/social"
	}
	if cfg.SessionContextKey == "" {
		cfg.SessionContextKey = "user"
	}
	if cfg.CookieName == "" {
		cfg.CookieName = cfg.SessionContextKey
	}
	if cfg.CookieSameSite == "" {
		cfg.CookieSameSite = "Lax"
	}
	if cfg.SuccessRedirect == "" {
		cfg.SuccessRedirect = "/"
	}
	if cfg.ErrorRedirect == "" {
		cfg.ErrorRedirect = "/login?error=auth_failed"
	}

	return &HTTPController{
		authenticator: auth,
		config:        cfg,
	}
}

// RegisterRoutes registers social auth routes.
func (c *HTTPController) RegisterRoutes(group RouteRegistrar) {
	group.Get("/providers", c.ListProviders)
	group.Get("/accounts", c.ListAccounts)
	group.Get("/:provider/callback", c.Callback)
	group.Post("/:provider/link", c.LinkAccount)
	group.Delete("/:provider", c.UnlinkAccount)
	group.Get("/:provider", c.BeginAuth)
}

// ListProviders returns available social providers.
func (c *HTTPController) ListProviders(ctx router.Context) error {
	providers := c.authenticator.ListProviders()
	return ctx.JSON(router.StatusOK, map[string]any{
		"providers": providers,
	})
}

// BeginAuth starts the OAuth flow.
func (c *HTTPController) BeginAuth(ctx router.Context) error {
	providerName := ctx.Param("provider")

	redirectURL := ctx.Query("redirect_url")
	if redirectURL == "" {
		redirectURL = c.config.SuccessRedirect
	}

	action := ctx.Query("action")
	if action == "" {
		action = ActionLogin
	}

	opts := []BeginAuthOption{
		ForAction(action),
		WithRedirectURL(redirectURL),
	}

	if action == ActionLink {
		userID := c.getUserIDFromSession(ctx)
		if userID == "" {
			return ctx.JSON(router.StatusUnauthorized, map[string]string{
				"error": "authentication required for linking",
			})
		}
		opts = append(opts, ForLinkingUser(userID))
	}

	redirect, err := c.authenticator.BeginAuth(ctx.Context(), providerName, opts...)
	if err != nil {
		return c.handleError(ctx, err)
	}

	return ctx.Redirect(redirect.URL, http.StatusTemporaryRedirect)
}

// Callback handles the OAuth callback.
func (c *HTTPController) Callback(ctx router.Context) error {
	providerName := ctx.Param("provider")
	code := ctx.Query("code")
	state := ctx.Query("state")

	if errCode := ctx.Query("error"); errCode != "" {
		errDesc := ctx.Query("error_description")
		redirectURL := appendQueryParam(c.config.ErrorRedirect, "oauth_error", errCode)
		if errDesc != "" {
			redirectURL = appendQueryParam(redirectURL, "desc", errDesc)
		}
		return ctx.Redirect(redirectURL, http.StatusTemporaryRedirect)
	}

	if code == "" || state == "" {
		redirectURL := appendQueryParam(c.config.ErrorRedirect, "error", "missing_params")
		return ctx.Redirect(redirectURL, http.StatusTemporaryRedirect)
	}

	result, err := c.authenticator.CompleteAuth(ctx.Context(), providerName, code, state)
	if err != nil {
		return c.handleError(ctx, err)
	}

	c.setAuthCookie(ctx, result.Token)

	redirectURL := result.RedirectURL
	if redirectURL == "" {
		redirectURL = c.config.SuccessRedirect
	}

	if result.IsNewUser {
		redirectURL = appendQueryParam(redirectURL, "new_user", "true")
	}

	return ctx.Redirect(redirectURL, http.StatusTemporaryRedirect)
}

// LinkAccount links a social account to the current user.
func (c *HTTPController) LinkAccount(ctx router.Context) error {
	userID := c.getUserIDFromSession(ctx)
	if userID == "" {
		return ctx.JSON(router.StatusUnauthorized, map[string]string{
			"error": "authentication required",
		})
	}

	providerName := ctx.Param("provider")

	redirect, err := c.authenticator.BeginAuth(ctx.Context(), providerName, ForLinkingUser(userID))
	if err != nil {
		return c.handleError(ctx, err)
	}

	return ctx.JSON(router.StatusOK, map[string]string{
		"redirect_url": redirect.URL,
	})
}

// UnlinkAccount removes a social account link.
func (c *HTTPController) UnlinkAccount(ctx router.Context) error {
	userID := c.getUserIDFromSession(ctx)
	if userID == "" {
		return ctx.JSON(router.StatusUnauthorized, map[string]string{
			"error": "authentication required",
		})
	}

	providerName := ctx.Param("provider")

	accounts, err := c.authenticator.accountRepo.FindByUserID(ctx.Context(), userID)
	if err != nil {
		return c.handleError(ctx, err)
	}

	if len(accounts) <= 1 {
		return ctx.JSON(router.StatusBadRequest, map[string]string{
			"error": ErrLastAuthMethod.Error(),
		})
	}

	if err := c.authenticator.accountRepo.DeleteByUserAndProvider(ctx.Context(), userID, providerName); err != nil {
		return c.handleError(ctx, err)
	}

	return ctx.JSON(router.StatusOK, map[string]string{
		"status": "unlinked",
	})
}

// ListAccounts returns linked social accounts for the current user.
func (c *HTTPController) ListAccounts(ctx router.Context) error {
	userID := c.getUserIDFromSession(ctx)
	if userID == "" {
		return ctx.JSON(router.StatusUnauthorized, map[string]string{
			"error": "authentication required",
		})
	}

	accounts, err := c.authenticator.accountRepo.FindByUserID(ctx.Context(), userID)
	if err != nil {
		return c.handleError(ctx, err)
	}

	response := make([]map[string]any, 0, len(accounts))
	for _, acc := range accounts {
		response = append(response, map[string]any{
			"id":               acc.ID,
			"provider":         acc.Provider,
			"provider_user_id": acc.ProviderUserID,
			"email":            acc.Email,
			"name":             acc.Name,
			"avatar_url":       acc.AvatarURL,
			"created_at":       acc.CreatedAt,
		})
	}

	return ctx.JSON(router.StatusOK, map[string]any{
		"accounts": response,
	})
}

func (c *HTTPController) getUserIDFromSession(ctx router.Context) string {
	session, err := auth.GetRouterSession(ctx, c.config.SessionContextKey)
	if err != nil {
		return ""
	}
	return session.GetUserID()
}

func (c *HTTPController) setAuthCookie(ctx router.Context, token string) {
	ctx.Cookie(&router.Cookie{
		Name:     c.config.CookieName,
		Value:    token,
		Path:     "/",
		Secure:   c.config.CookieSecure,
		HTTPOnly: c.config.CookieHTTPOnly,
		SameSite: c.config.CookieSameSite,
	})
}

func (c *HTTPController) handleError(ctx router.Context, err error) error {
	if c.config.ErrorHandler != nil {
		return c.config.ErrorHandler(ctx, err)
	}

	redirectURL := appendQueryParam(c.config.ErrorRedirect, "error", err.Error())
	return ctx.Redirect(redirectURL, http.StatusTemporaryRedirect)
}

func appendQueryParam(rawURL, key, value string) string {
	if rawURL == "" {
		return ""
	}

	parsed, err := url.Parse(rawURL)
	if err == nil {
		query := parsed.Query()
		query.Set(key, value)
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}

	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value)
}
