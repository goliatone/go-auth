package csrf

import "github.com/goliatone/go-router"

// RouteConfig controls how the CSRF token bootstrap endpoint behaves.
type RouteConfig struct {
	// Path is the route registered for retrieving the CSRF token.
	Path string
	// ContextKey is the context key where the middleware stored the token.
	ContextKey string
	// RouteName is the name assigned to the registered route.
	RouteName string
}

const (
	defaultRoutePath = "/csrf"
	defaultRouteName = "auth.csrf.get"
)

// RegisterRoutes registers a GET endpoint that returns the CSRF token and
// related metadata (form field and header names). It expects the CSRF
// middleware to have already populated the request context with a token.
func RegisterRoutes[T any](app router.Router[T], cfg ...RouteConfig) {
	conf := routeConfigDefault(cfg...)
	app.Get(conf.Path, tokenHandler(conf)).SetName(conf.RouteName)
}

func routeConfigDefault(cfg ...RouteConfig) RouteConfig {
	conf := RouteConfig{
		Path:       defaultRoutePath,
		ContextKey: DefaultContextKey,
		RouteName:  defaultRouteName,
	}
	if len(cfg) == 0 {
		return conf
	}

	c := cfg[0]
	if c.Path != "" {
		conf.Path = c.Path
	}

	if c.ContextKey != "" {
		conf.ContextKey = c.ContextKey
	}

	if c.RouteName != "" {
		conf.RouteName = c.RouteName
	}

	return conf
}

func tokenHandler(cfg RouteConfig) router.HandlerFunc {
	return func(ctx router.Context) error {
		token, _ := ctx.Locals(cfg.ContextKey).(string)
		if token == "" {
			return ctx.JSON(router.StatusUnauthorized, map[string]string{
				"error": ErrTokenMissing.Error(),
			})
		}

		ctx.SetHeader("Cache-Control", "no-store, max-age=0")
		ctx.SetHeader("Pragma", "no-cache")
		ctx.SetHeader("Expires", "0")

		fieldName := DefaultFormFieldName
		if v, ok := ctx.Locals(cfg.ContextKey + "_field").(string); ok && v != "" {
			fieldName = v
		}

		headerName := DefaultHeaderName
		if v, ok := ctx.Locals(cfg.ContextKey + "_header").(string); ok && v != "" {
			headerName = v
		}

		return ctx.JSON(router.StatusOK, map[string]string{
			"token":       token,
			"field_name":  fieldName,
			"header_name": headerName,
		})
	}
}
