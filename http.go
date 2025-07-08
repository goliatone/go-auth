package auth

import (
	"net/http"
	"time"

	"github.com/goliatone/go-auth/middleware/jwtware"
	"github.com/goliatone/go-errors"
	"github.com/goliatone/go-print"
	"github.com/goliatone/go-router"
)

type RouteAuthenticator struct {
	auth                   Authenticator
	cfg                    Config
	registry               AccountRegistrerer
	cookieDuration         time.Duration
	extendedCookieDuration time.Duration
	Logger                 Logger
	AuthErrorHandler       func(c router.Context, err error) error // TODO: make functions
	ErrorHandler           func(c router.Context, err error) error // TODO: make functions
}

func NewHTTPAuthenticator(auther Authenticator, cfg Config) (*RouteAuthenticator, error) {
	cookieDuration := 24 * time.Hour
	if cfg.GetTokenExpiration() > 0 {
		cookieDuration = time.Duration(cfg.GetTokenExpiration()) * time.Hour
	}

	extendedCookieDuration := cookieDuration
	if cfg.GetExtendedTokenDuration() > 0 {
		extendedCookieDuration = time.Duration(cfg.GetExtendedTokenDuration()) * time.Hour
	}

	a := &RouteAuthenticator{
		cfg:                    cfg,
		auth:                   auther,
		Logger:                 defLogger{},
		cookieDuration:         cookieDuration,
		extendedCookieDuration: extendedCookieDuration,
	}

	a.ErrorHandler = a.defaultErrHandler
	a.AuthErrorHandler = a.defaultAuthErrHandler

	return a, nil
}

func (a RouteAuthenticator) GetCookieDuration() time.Duration {
	return a.cookieDuration
}

func (a RouteAuthenticator) GetExtendedCookieDuration() time.Duration {
	return a.extendedCookieDuration
}

func (a *RouteAuthenticator) ProtectedRoute(cfg Config, errorHandler func(router.Context, error) error) router.MiddlewareFunc {
	return func(hf router.HandlerFunc) router.HandlerFunc {
		return jwtware.New(jwtware.Config{
			ErrorHandler: errorHandler,
			SigningKey: jwtware.SigningKey{
				Key:    []byte(cfg.GetSigningKey()),
				JWTAlg: cfg.GetSigningMethod(),
			},
			AuthScheme:  cfg.GetAuthScheme(),
			ContextKey:  cfg.GetContextKey(),
			TokenLookup: cfg.GetTokenLookup(),
		})
	}
}

func (a *RouteAuthenticator) Login(ctx router.Context, payload LoginPayload) error {
	token, err := a.auth.Login(ctx.Context(), payload.GetIdentifier(), payload.GetPassword())
	if err != nil {
		a.Logger.Error("Login error: %s", err)
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
			a.Logger.Info("Optional auth failed, proceeding", "error", richErr.Message)
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
	refererHeader := string(ctx.Referer())

	r := ctx.Cookies(rejectedRoute, refererHeader)
	if r == "" {
		r = a.cfg.GetRejectedRouteDefault()
	}
	a.cookieDel(ctx, rejectedRoute)
	return r
}

func (a *RouteAuthenticator) SetRedirect(ctx router.Context) {
	rejectedRoute := a.cfg.GetRejectedRouteKey()

	a.Logger.Info("Setting redirect cookie", "key", rejectedRoute, "path", ctx.OriginalURL())

	ctx.Cookie(&router.Cookie{
		Name:     rejectedRoute,
		Value:    ctx.OriginalURL(),
		Expires:  time.Now().Add(time.Minute * 5),
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
	})
}

func (a *RouteAuthenticator) Impersonate(c router.Context, identifier string) error {
	token, err := a.auth.Impersonate(c.Context(), identifier)
	if err != nil {
		a.Logger.Error("Impersonate authentication error", "error", err)
		return err
	}

	a.setCookieToken(c, token, a.cookieDuration)
	return nil
}

func (a *RouteAuthenticator) setCookieToken(c router.Context, val string, duration time.Duration) {
	c.Cookie(&router.Cookie{
		Name:     a.cfg.GetContextKey(),
		Value:    val,
		Expires:  time.Now().Add(duration),
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
	})
}

func (a *RouteAuthenticator) cookieDel(c router.Context, name string) {
	c.Cookie(&router.Cookie{
		Name:     name,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour * (24 * 365)),
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
	})
}

func (a *RouteAuthenticator) defaultAuthErrHandler(c router.Context, err error) error {
	var richErr *errors.Error
	if !errors.As(err, &richErr) {
		richErr = errors.Wrap(richErr, errors.CategoryAuth, "An unexpected authentication error").
			WithCode(errors.CodeUnauthorized)
	}

	a.Logger.Info(
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

	a.Logger.Info(
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
