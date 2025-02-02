package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/goliatone/go-auth/middleware/jwtware"
	"github.com/goliatone/go-router"
)

type RouteController struct {
	auth                   Authenticator
	cfg                    Config
	registry               AccountRegistrerer
	cookieDuration         time.Duration
	extendedCookieDuration time.Duration
	AuthErrorHandler       func(c router.Context) error
	ErrorHandler           func(c router.Context, err error) error
}

func NewRouteController(auther Authenticator, cfg Config) (*RouteController, error) {
	cookieDuration := 24 * time.Hour
	if cfg.GetTokenExpiration() > 0 {
		cookieDuration = time.Duration(cfg.GetTokenExpiration()) * time.Hour
	}

	extendedCookieDuration := cookieDuration
	if cfg.GetExtendedTokenDuration() > 0 {
		extendedCookieDuration = time.Duration(cfg.GetExtendedTokenDuration()) * time.Hour
	}

	a := &RouteController{
		cfg:                    cfg,
		auth:                   auther,
		cookieDuration:         cookieDuration,
		extendedCookieDuration: extendedCookieDuration,
	}

	a.ErrorHandler = a.defaultErrHandler
	a.AuthErrorHandler = a.defaultAuthErrHandler

	return a, nil
}

func (a *RouteController) ProtectedRoute(cfg Config, errorHandler func(router.Context, error) error) router.MiddlewareFunc {
	return func(hf router.HandlerFunc) router.HandlerFunc {
		return jwtware.New(jwtware.Config{
			ErrorHandler: errorHandler,
			SigningKey: jwtware.SigningKey{
				Key:    cfg.GetSigningKey(),
				JWTAlg: cfg.GetSigningMethod(),
			},
			AuthScheme:  cfg.GetAuthScheme(),
			ContextKey:  cfg.GetContextKey(),
			TokenLookup: cfg.GetTokenLookup(),
		})
	}
}

func (a *RouteController) Login(ctx router.Context, payload LoginPayload) error {
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

func (a *RouteController) Logout(ctx router.Context) {
	a.cookieDel(ctx, a.cfg.GetContextKey())
}

func (a *RouteController) MakeClientRouteAuthErrorHandler(optional bool) func(router.Context, error) error {
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

func (a *RouteController) GetRedirect(ctx router.Context, def ...string) string {
	rejectedRoute := a.cfg.GetRejectedRouteKey()
	r := ctx.Cookies(rejectedRoute)
	if r == "" {
		return def[0]
	}
	a.cookieDel(ctx, rejectedRoute)
	return r
}

func (a *RouteController) GetRedirectOrDefault(ctx router.Context) string {
	rejectedRoute := a.cfg.GetRejectedRouteKey()
	refererHeader := string(ctx.Referer())

	r := ctx.Cookies(rejectedRoute, refererHeader)
	if r == "" {
		r = a.cfg.GetRejectedRouteDefault()
	}
	a.cookieDel(ctx, rejectedRoute)
	return r
}

func (a *RouteController) SetRedirect(ctx router.Context) {
	rejectedRoute := a.cfg.GetRejectedRouteKey()
	ctx.Cookie(&router.Cookie{
		Name:     rejectedRoute,
		Value:    ctx.OriginalURL(),
		Expires:  time.Now().Add(time.Minute * 5),
		HTTPOnly: true,
	})
}

func (a *RouteController) Impersonate(c router.Context, identifier string) error {
	token, err := a.auth.Impersonate(c.Context(), identifier)
	if err != nil {
		return fmt.Errorf("authentication error: %w", err)
	}
	a.setCookieToken(c, token, a.cookieDuration)
	return nil
}

func (a *RouteController) setCookieToken(c router.Context, val string, duration time.Duration) {
	c.Cookie(&router.Cookie{
		Name:     a.cfg.GetContextKey(),
		Value:    val,
		Expires:  time.Now().Add(duration),
		HTTPOnly: true,
	})
}

func (a *RouteController) cookieDel(c router.Context, name string) {
	c.Cookie(&router.Cookie{
		Name:     name,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour * (24 * 365)),
		HTTPOnly: true,
	})
}

func (a *RouteController) defaultAuthErrHandler(c router.Context) error {
	a.SetRedirect(c)
	return c.Redirect("/login", http.StatusSeeOther)
}

func (a *RouteController) defaultErrHandler(c router.Context, err error) error {
	return c.Render("errors/500", router.ViewContext{
		"message": err.Error(),
	})
}
