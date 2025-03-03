package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/goliatone/go-auth/middleware/jwtware"
	"github.com/goliatone/go-router"
)

type RouteAuthenticator struct {
	auth                   Authenticator
	cfg                    Config
	registry               AccountRegistrerer
	cookieDuration         time.Duration
	extendedCookieDuration time.Duration
	// TODO: make functions
	AuthErrorHandler func(c router.Context) error
	ErrorHandler     func(c router.Context, err error) error
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
		return fmt.Errorf("err authenticating payload: %w", err)
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
		if IsMalformedError(err) {
			// Some routes might optionally be protected
			if optional {
				return ctx.Next()
			}
			return a.AuthErrorHandler(ctx)
		}
		return a.ErrorHandler(ctx, err)
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
	ctx.Cookie(&router.Cookie{
		Name:     rejectedRoute,
		Value:    ctx.OriginalURL(),
		Expires:  time.Now().Add(time.Minute * 5),
		HTTPOnly: true,
	})
}

func (a *RouteAuthenticator) Impersonate(c router.Context, identifier string) error {
	token, err := a.auth.Impersonate(c.Context(), identifier)
	if err != nil {
		return fmt.Errorf("authentication error: %w", err)
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
	})
}

func (a *RouteAuthenticator) cookieDel(c router.Context, name string) {
	c.Cookie(&router.Cookie{
		Name:     name,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour * (24 * 365)),
		HTTPOnly: true,
	})
}

func (a *RouteAuthenticator) defaultAuthErrHandler(c router.Context) error {
	a.SetRedirect(c)
	return c.Redirect("/login", http.StatusSeeOther)
}

func (a *RouteAuthenticator) defaultErrHandler(c router.Context, err error) error {
	return c.Render("errors/500", router.ViewContext{
		"message": err.Error(),
	})
}
