package auth

import (
	"net/http"
	"strings"
	"time"

	csrf "github.com/goliatone/go-auth/middleware/csrf"
	"github.com/goliatone/go-router"
)

type RouteAuthenticationMode string

const (
	RouteAuthenticationProviderSession RouteAuthenticationMode = "provider_session"
	RouteAuthenticationLocalJWT        RouteAuthenticationMode = "local_jwt"
	RouteAuthenticationBearer          RouteAuthenticationMode = "bearer"
)

type RouteCredentialConfig struct {
	Mode                  RouteAuthenticationMode
	ProviderSessionCookie string
	LocalJWTCookie        string
	ErrorHandler          func(router.Context, error) error
}

//nolint:gocyclo // Credential mode combinations are checked explicitly to prevent downgrade paths.
func CredentialModeGuard(cfg RouteCredentialConfig) (router.MiddlewareFunc, error) {
	cfg.ProviderSessionCookie = strings.TrimSpace(cfg.ProviderSessionCookie)
	cfg.LocalJWTCookie = strings.TrimSpace(cfg.LocalJWTCookie)
	if cfg.ProviderSessionCookie == "" {
		cfg.ProviderSessionCookie = DefaultProviderSessionCookieName
	}
	switch cfg.Mode {
	case RouteAuthenticationProviderSession:
	case RouteAuthenticationLocalJWT:
		if cfg.LocalJWTCookie == "" {
			return nil, ErrProviderSessionInvalid
		}
	case RouteAuthenticationBearer:
	default:
		return nil, ErrProviderSessionInvalid
	}
	if cfg.ProviderSessionCookie == cfg.LocalJWTCookie && cfg.LocalJWTCookie != "" {
		return nil, ErrProviderSessionInvalid
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(c router.Context, _ error) error {
			return c.SendStatus(http.StatusUnauthorized)
		}
	}
	return func(next router.HandlerFunc) router.HandlerFunc {
		return func(c router.Context) error {
			provider := strings.TrimSpace(c.Cookies(cfg.ProviderSessionCookie)) != ""
			local := cfg.LocalJWTCookie != "" && strings.TrimSpace(c.Cookies(cfg.LocalJWTCookie)) != ""
			bearer := strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.Header("Authorization"))), "bearer ")
			count := 0
			for _, present := range []bool{provider, local, bearer} {
				if present {
					count++
				}
			}
			if count > 1 {
				return cfg.ErrorHandler(c, ErrProviderSessionCredential)
			}
			selected := (cfg.Mode == RouteAuthenticationProviderSession && provider) ||
				(cfg.Mode == RouteAuthenticationLocalJWT && local) ||
				(cfg.Mode == RouteAuthenticationBearer && bearer)
			if !selected {
				return cfg.ErrorHandler(c, ErrProviderSessionNotFound)
			}
			return next(c)
		}
	}, nil
}

type ProviderSessionHTTPConfig struct {
	Resolver       ProviderSessionResolver
	Binding        ProviderSessionBinding
	Cookie         router.Cookie
	CookieDuration time.Duration
	AllowDomain    bool
	LocalJWTCookie string
	ContextKey     string
	CSRF           csrf.Config
	Origin         router.OriginProtectionConfig
	ErrorHandler   func(router.Context, error) error
}

type ProviderSessionHTTP struct {
	resolver       ProviderSessionResolver
	binding        ProviderSessionBinding
	cookie         router.Cookie
	cookieDuration time.Duration
	localJWTCookie string
	contextKey     string
	csrf           csrf.Config
	origin         router.OriginProtectionConfig
	errorHandler   func(router.Context, error) error
	credentialMode router.MiddlewareFunc
}

//nolint:gocyclo // Cookie, binding, and CSRF invariants are validated at construction.
func NewProviderSessionHTTP(cfg ProviderSessionHTTPConfig) (*ProviderSessionHTTP, error) {
	if cfg.Resolver == nil {
		return nil, ErrProviderSessionInvalid
	}
	if err := cfg.Binding.Validate(); err != nil {
		return nil, err
	}
	cookie := cfg.Cookie
	if strings.TrimSpace(cookie.Name) == "" {
		cookie.Name = DefaultProviderSessionCookieName
	}
	if strings.TrimSpace(cookie.Path) == "" {
		cookie.Path = "/"
	}
	if strings.TrimSpace(cookie.SameSite) == "" {
		cookie.SameSite = router.CookieSameSiteLaxMode
	}
	cookie.Secure = true
	cookie.HTTPOnly = true
	if strings.HasPrefix(cookie.Name, "__Host-") && (cookie.Path != "/" || strings.TrimSpace(cookie.Domain) != "") {
		return nil, ErrProviderSessionInvalid
	}
	if strings.TrimSpace(cookie.Domain) != "" && !cfg.AllowDomain {
		return nil, ErrProviderSessionInvalid
	}
	if err := router.ValidateCookie(cookie); err != nil {
		return nil, err
	}
	if cfg.CookieDuration <= 0 {
		return nil, ErrProviderSessionInvalid
	}
	if strings.TrimSpace(cfg.ContextKey) == "" {
		cfg.ContextKey = "provider_principal"
	}
	if cfg.CSRF.Storage == nil && len(cfg.CSRF.SecureKey) == 0 {
		return nil, csrf.ErrSecureKeyMissing
	}
	if cfg.CSRF.SessionKeyResolver == nil {
		cfg.CSRF.SessionKeyResolver = providerSessionCSRFKey
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(c router.Context, _ error) error {
			return c.SendStatus(http.StatusUnauthorized)
		}
	}
	guard, err := CredentialModeGuard(RouteCredentialConfig{
		Mode:                  RouteAuthenticationProviderSession,
		ProviderSessionCookie: cookie.Name,
		LocalJWTCookie:        cfg.LocalJWTCookie,
		ErrorHandler:          cfg.ErrorHandler,
	})
	if err != nil {
		return nil, err
	}
	if cfg.Origin.ErrorHandler == nil {
		cfg.Origin.ErrorHandler = func(c router.Context, _ error) error {
			return c.SendStatus(http.StatusForbidden)
		}
	}
	return &ProviderSessionHTTP{
		resolver:       cfg.Resolver,
		binding:        cfg.Binding.normalized(),
		cookie:         cookie,
		cookieDuration: cfg.CookieDuration,
		localJWTCookie: strings.TrimSpace(cfg.LocalJWTCookie),
		contextKey:     cfg.ContextKey,
		csrf:           cfg.CSRF,
		origin:         cfg.Origin,
		errorHandler:   cfg.ErrorHandler,
		credentialMode: guard,
	}, nil
}

func (h *ProviderSessionHTTP) Middleware() router.MiddlewareFunc {
	return func(next router.HandlerFunc) router.HandlerFunc {
		resolver := func(c router.Context) error {
			raw := strings.TrimSpace(c.Cookies(h.cookie.Name))
			session, principal, err := h.resolver.ResolveProviderSession(c.Context(), NewSecret(raw), h.binding)
			if err != nil {
				h.ClearCookie(c)
				return h.errorHandler(c, err)
			}
			c.Locals(h.contextKey, principal.Clone())
			c.Locals("session_id", session.LocalSessionID)
			c.Locals("user_id", principal.ApplicationSubject())
			c.SetContext(WithProviderSessionContext(c.Context(), session, principal))

			csrfCfg := h.csrf
			csrfCfg.SuccessHandler = next
			return router.OriginProtection(h.origin)(csrf.New(csrfCfg)(next))(c)
		}
		return h.credentialMode(resolver)
	}
}

func (h *ProviderSessionHTTP) SetCookie(c router.Context, handle Secret) error {
	if h == nil || c == nil || handle.IsZero() {
		return ErrProviderSessionInvalid
	}
	cookie := h.cookie
	cookie.Value = handle.Reveal()
	cookie.Expires = time.Now().UTC().Add(h.cookieDuration)
	cookie.MaxAge = int(h.cookieDuration.Seconds())
	cookie.SessionOnly = false
	c.Cookie(&cookie)
	return nil
}

func (h *ProviderSessionHTTP) ClearCookie(c router.Context) {
	if h == nil || c == nil {
		return
	}
	cookie := h.cookie
	cookie.Value = ""
	cookie.Expires = time.Unix(1, 0).UTC()
	cookie.MaxAge = -1
	cookie.SessionOnly = false
	c.Cookie(&cookie)
}

func (h *ProviderSessionHTTP) RotateCookie(c router.Context, manager *ProviderSessionManager) error {
	if h == nil || manager == nil || c == nil {
		return ErrProviderSessionInvalid
	}
	current := NewSecret(strings.TrimSpace(c.Cookies(h.cookie.Name)))
	next, _, err := manager.RotateProviderSessionHandle(c.Context(), current, h.binding)
	if err != nil {
		h.ClearCookie(c)
		return err
	}
	return h.SetCookie(c, next)
}

func providerSessionCSRFKey(c router.Context) (string, bool) {
	if c == nil {
		return "", false
	}
	sessionID := strings.TrimSpace(c.GetString("session_id", ""))
	if sessionID == "" {
		if local, ok := c.Locals("session_id").(string); ok {
			sessionID = strings.TrimSpace(local)
		}
	}
	if sessionID == "" {
		return "", false
	}
	return "csrf_" + sessionID, true
}
