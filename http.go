package auth

import (
	"net/http"
	"strings"
	"time"

	csrf "github.com/goliatone/go-auth/middleware/csrf"
	"github.com/goliatone/go-auth/middleware/jwtware"
	"github.com/goliatone/go-errors"
	"github.com/goliatone/go-print"
	"github.com/goliatone/go-router"
)

// TokenServiceAdapter adapts TokenValidator to jwtware.TokenValidator interface
type TokenServiceAdapter struct {
	tokenValidator TokenValidator
}

// NewTokenServiceAdapter creates a new TokenServiceAdapter
func NewTokenServiceAdapter(tokenValidator TokenValidator) *TokenServiceAdapter {
	return &TokenServiceAdapter{
		tokenValidator: tokenValidator,
	}
}

// Validate implements the jwtware.TokenValidator interface
func (tsa *TokenServiceAdapter) Validate(tokenString string) (jwtware.AuthClaims, error) {
	if tsa.tokenValidator == nil {
		return nil, ErrUnableToDecodeSession
	}
	return tsa.tokenValidator.Validate(tokenString)
}

type RouteAuthenticator struct {
	auth                   Authenticator
	cfg                    Config
	registry               AccountRegistrerer
	cookieDuration         time.Duration
	extendedCookieDuration time.Duration
	authCookieTemplate     router.Cookie
	redirectCookieTemplate router.Cookie
	logger                 Logger
	loggerProvider         LoggerProvider
	AuthErrorHandler       func(c router.Context, err error) error // TODO: make functions
	ErrorHandler           func(c router.Context, err error) error // TODO: make functions
	validationListeners    []ValidationListener
}

type HTTPAuthenticatorOption func(*RouteAuthenticator) error

type BrowserProtectionConfig struct {
	AuthCookieName string
	CSRF           csrf.Config
	Origin         router.OriginProtectionConfig
}

func WithAuthCookieTemplate(cookie router.Cookie) HTTPAuthenticatorOption {
	return func(a *RouteAuthenticator) error {
		if err := router.ValidateCookie(cookie); err != nil {
			return err
		}
		a.authCookieTemplate = cookie
		return nil
	}
}

func WithRedirectCookieTemplate(cookie router.Cookie) HTTPAuthenticatorOption {
	return func(a *RouteAuthenticator) error {
		if err := router.ValidateCookie(cookie); err != nil {
			return err
		}
		a.redirectCookieTemplate = cookie
		return nil
	}
}

func NewHTTPAuthenticator(auther Authenticator, cfg Config, opts ...HTTPAuthenticatorOption) (*RouteAuthenticator, error) {
	cookieDuration := 24 * time.Hour
	if cfg.GetTokenExpiration() > 0 {
		cookieDuration = time.Duration(cfg.GetTokenExpiration()) * time.Hour
	}

	extendedCookieDuration := cookieDuration
	if cfg.GetExtendedTokenDuration() > 0 {
		extendedCookieDuration = time.Duration(cfg.GetExtendedTokenDuration()) * time.Hour
	}

	loggerProvider, logger := ResolveLogger("auth.http", nil, nil)
	a := &RouteAuthenticator{
		cfg:                    cfg,
		auth:                   auther,
		logger:                 logger,
		loggerProvider:         loggerProvider,
		cookieDuration:         cookieDuration,
		extendedCookieDuration: extendedCookieDuration,
		authCookieTemplate:     router.FirstPartySessionCookie("", ""),
		redirectCookieTemplate: router.Cookie{Path: "/", HTTPOnly: true, Secure: true, SameSite: router.CookieSameSiteLaxMode},
	}

	a.ErrorHandler = a.defaultErrHandler
	a.AuthErrorHandler = a.defaultAuthErrHandler

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(a); err != nil {
			return nil, err
		}
	}

	return a, nil
}

func (a *RouteAuthenticator) WithLogger(l Logger) *RouteAuthenticator {
	a.loggerProvider, a.logger = ResolveLogger("auth.http", a.loggerProvider, l)
	return a
}

// WithLoggerProvider overrides the logger provider used by the HTTP authenticator.
func (a *RouteAuthenticator) WithLoggerProvider(provider LoggerProvider) *RouteAuthenticator {
	a.loggerProvider, a.logger = ResolveLogger("auth.http", provider, a.logger)
	return a
}

// WithValidationListeners registers callbacks invoked immediately after token validation.
func (a *RouteAuthenticator) WithValidationListeners(listeners ...ValidationListener) *RouteAuthenticator {
	if len(listeners) == 0 {
		return a
	}
	a.validationListeners = append(a.validationListeners, listeners...)
	return a
}

func (a RouteAuthenticator) GetCookieDuration() time.Duration {
	return a.cookieDuration
}

func (a RouteAuthenticator) GetExtendedCookieDuration() time.Duration {
	return a.extendedCookieDuration
}

func (a *RouteAuthenticator) ProtectedRoute(cfg Config, errorHandler func(router.Context, error) error) router.MiddlewareFunc {
	jwtConfig := jwtware.Config{
		ErrorHandler: errorHandler,
		SigningKey: jwtware.SigningKey{
			Key:    []byte(cfg.GetSigningKey()),
			JWTAlg: cfg.GetSigningMethod(),
		},
		AuthScheme:      cfg.GetAuthScheme(),
		ContextKey:      cfg.GetContextKey(),
		TokenLookup:     cfg.GetTokenLookup(),
		ContextEnricher: ContextEnricherAdapter,
	}

	if len(a.validationListeners) > 0 {
		RegisterValidationListeners(&jwtConfig, a.validationListeners...)
	}

	// If the Auther has a TokenValidator, use it for enhanced validation
	if auther, ok := a.auth.(*Auther); ok {
		validator := auther.tokenValidator
		if validator == nil {
			validator = auther.tokenService
		}
		if validator != nil {
			jwtConfig.TokenValidator = NewTokenServiceAdapter(validator)
		}
	}

	return jwtware.New(jwtConfig)
}

func (a *RouteAuthenticator) ProtectedBrowserRoute(cfg Config, errorHandler func(router.Context, error) error, config ...BrowserProtectionConfig) router.MiddlewareFunc {
	jwtMiddleware := a.ProtectedRoute(cfg, errorHandler)
	securityCfg := browserProtectionConfigDefault(config, cfg)
	originMiddleware := router.OriginProtection(securityCfg.Origin)

	return func(next router.HandlerFunc) router.HandlerFunc {
		csrfCfg := securityCfg.CSRF
		csrfCfg.SuccessHandler = func(c router.Context) error {
			return next(c)
		}
		csrfMiddleware := csrf.New(csrfCfg)
		protectedHandler := func(c router.Context) error {
			if requestUsesCookieAuth(c, securityCfg.AuthCookieName) {
				return originMiddleware(csrfMiddleware(next))(c)
			}
			if methodRequiresProtection(c.Method(), securityCfg.CSRF.SafeMethods) {
				return next(c)
			}
			return csrfMiddleware(next)(c)
		}
		return jwtMiddleware(protectedHandler)
	}
}

func (a *RouteAuthenticator) Login(ctx router.Context, payload LoginPayload) error {
	token, err := a.auth.Login(ctx.Context(), payload.GetIdentifier(), payload.GetPassword())
	if err != nil {
		a.logger.Error("Login error", "error", err)
		return err
	}

	duration := a.cookieDuration
	if payload.GetExtendedSession() {
		duration = a.extendedCookieDuration
	}

	a.setCookieToken(ctx, token, duration)
	return nil
}

func (a *RouteAuthenticator) Logout(ctx router.Context) {
	a.cookieDel(ctx, a.cfg.GetContextKey())
}

func (a *RouteAuthenticator) MakeClientRouteAuthErrorHandler(optional bool) func(router.Context, error) error {
	return func(ctx router.Context, err error) error {
		var richErr *errors.Error

		if IsTokenExpiredError(err) {
			richErr = ErrTokenExpired
		} else if IsMalformedError(err) {
			richErr = ErrTokenMalformed
		} else {
			richErr = errors.Wrap(err, errors.CategoryAuth, "Invalid authentication token").
				WithCode(errors.CodeUnauthorized)
		}

		if optional {
			a.logger.Info("Optional auth failed, proceeding", "error", richErr.Message)
			return ctx.Next()
		}

		return a.ErrorHandler(ctx, richErr)
	}
}

func (a *RouteAuthenticator) GetRedirect(ctx router.Context, def ...string) string {
	rejectedRoute := a.cfg.GetRejectedRouteKey()
	r := ctx.Cookies(rejectedRoute)
	if r == "" {
		return def[0]
	}
	a.cookieDel(ctx, rejectedRoute)
	return r
}

func (a *RouteAuthenticator) GetRedirectOrDefault(ctx router.Context) string {
	rejectedRoute := a.cfg.GetRejectedRouteKey()
	refererHeader := router.ResolveRedirectBackTarget(ctx, "")

	r := ctx.Cookies(rejectedRoute, refererHeader)
	if r == "" {
		r = a.cfg.GetRejectedRouteDefault()
	}
	a.cookieDel(ctx, rejectedRoute)
	return r
}

func (a *RouteAuthenticator) SetRedirect(ctx router.Context) {
	rejectedRoute := a.cfg.GetRejectedRouteKey()

	a.logger.Info("Setting redirect cookie", "key", rejectedRoute, "path", ctx.OriginalURL())

	ctx.Cookie(&router.Cookie{
		Name:     rejectedRoute,
		Value:    ctx.OriginalURL(),
		Path:     firstNonEmptyString(a.redirectCookieTemplate.Path, "/"),
		Expires:  time.Now().Add(time.Minute * 5),
		HTTPOnly: a.redirectCookieTemplate.HTTPOnly,
		Secure:   a.redirectCookieTemplate.Secure,
		SameSite: router.NormalizeCookieSameSite(a.redirectCookieTemplate.SameSite),
	})
}

func (a *RouteAuthenticator) Impersonate(c router.Context, identifier string) error {
	token, err := a.auth.Impersonate(c.Context(), identifier)
	if err != nil {
		a.logger.Error("Impersonate authentication error", "error", err)
		return err
	}

	a.setCookieToken(c, token, a.cookieDuration)
	return nil
}

func (a *RouteAuthenticator) setCookieToken(c router.Context, val string, duration time.Duration) {
	cookie := a.authCookieTemplate
	cookie.Name = a.cfg.GetContextKey()
	cookie.Value = val
	cookie.Expires = time.Now().Add(duration)
	cookie.SessionOnly = false
	c.Cookie(&cookie)
}

func (a *RouteAuthenticator) cookieDel(c router.Context, name string) {
	cookie := a.authCookieTemplate
	cookie.Name = name
	cookie.Value = ""
	cookie.Expires = time.Now().Add(-time.Hour * (24 * 365))
	cookie.SessionOnly = false
	c.Cookie(&cookie)
}

func (a *RouteAuthenticator) defaultAuthErrHandler(c router.Context, err error) error {
	var richErr *errors.Error
	if !errors.As(err, &richErr) {
		richErr = errors.Wrap(richErr, errors.CategoryAuth, "An unexpected authentication error").
			WithCode(errors.CodeUnauthorized)
	}

	a.logger.Warn(
		"Authentication error, redirecting to loing",
		"error", richErr.Message,
		"text_code", richErr.TextCode,
		"path", c.OriginalURL(),
	)

	a.SetRedirect(c)

	statusCode := http.StatusSeeOther
	if c.Method() == string(router.GET) {
		statusCode = http.StatusFound
	}
	return c.Redirect("/login", statusCode)
}

func (a *RouteAuthenticator) defaultErrHandler(c router.Context, err error) error {
	var richErr *errors.Error
	if !errors.As(err, &richErr) {
		richErr = errors.Wrap(err, errors.CategoryInternal, "An unexpected server error occurred").
			WithCode(errors.CodeInternal)
	}

	a.logger.Warn(
		"Middleware error handler",
		"error", richErr.Message,
		"category", richErr.Category,
		"details", print.MaybePrettyJSON(richErr.Metadata),
	)

	switch richErr.Category {
	case errors.CategoryAuth, errors.CategoryAuthz:
		return a.AuthErrorHandler(c, richErr)
	default:
		return c.Status(richErr.Code).Render("errors/500", router.ViewContext{
			"error": richErr,
		})
	}
}

func browserProtectionConfigDefault(config []BrowserProtectionConfig, authCfg Config) BrowserProtectionConfig {
	cfg := BrowserProtectionConfig{}
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg.AuthCookieName = strings.TrimSpace(cfg.AuthCookieName)
	if cfg.AuthCookieName == "" {
		cfg.AuthCookieName = authCookieNameFromTokenLookup(authCfg)
	}
	if cfg.AuthCookieName == "" {
		cfg.AuthCookieName = authCfg.GetContextKey()
	}
	if cfg.CSRF.SessionKeyResolver == nil {
		cfg.CSRF.SessionKeyResolver = browserCSRFSessionKeyResolver
	}
	if cfg.Origin.ErrorHandler == nil {
		cfg.Origin.ErrorHandler = func(c router.Context, err error) error {
			return c.Status(http.StatusForbidden).SendString("forbidden")
		}
	}
	return cfg
}

func browserCSRFSessionKeyResolver(c router.Context) (string, bool) {
	if c == nil {
		return "", false
	}
	if sessionID := strings.TrimSpace(c.GetString("session_id", "")); sessionID != "" {
		return "csrf_" + sessionID, true
	}
	if userID := strings.TrimSpace(c.GetString("user_id", "")); userID != "" {
		return "csrf_user_" + userID, true
	}
	if claims, ok := GetClaims(c.Context()); ok && claims != nil {
		if tokenIDer, ok := claims.(interface{ TokenID() string }); ok {
			if tokenID := strings.TrimSpace(tokenIDer.TokenID()); tokenID != "" {
				return "csrf_session_" + tokenID, true
			}
		}
		if userID := strings.TrimSpace(claims.UserID()); userID != "" {
			return "csrf_user_" + userID, true
		}
	}
	if actor, ok := ActorFromContext(c.Context()); ok && actor != nil {
		if actorID := strings.TrimSpace(actor.ActorID); actorID != "" {
			return "csrf_user_" + actorID, true
		}
	}
	return "", false
}

func authCookieNameFromTokenLookup(cfg Config) string {
	for _, part := range strings.Split(cfg.GetTokenLookup(), ",") {
		part = strings.TrimSpace(part)
		if after, ok := strings.CutPrefix(part, "cookie:"); ok {
			return strings.TrimSpace(after)
		}
	}
	return ""
}

func requestUsesCookieAuth(c router.Context, cookieName string) bool {
	if c == nil || strings.TrimSpace(cookieName) == "" {
		return false
	}
	return strings.TrimSpace(c.Cookies(cookieName)) != ""
}

func methodRequiresProtection(method string, safeMethods []string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, safe := range safeMethods {
		if method == strings.ToUpper(strings.TrimSpace(safe)) {
			return false
		}
	}
	return true
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
