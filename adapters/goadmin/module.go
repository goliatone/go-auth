package goadmin

import (
	"fmt"
	"strings"

	"github.com/goliatone/go-admin/admin"
	"github.com/goliatone/go-admin/admin/routing"
	router "github.com/goliatone/go-router"
)

const (
	ModuleID = "go_auth_sso"

	RouteProviderList = "sso.providers"
	RouteBeginLogin   = "sso.begin"
	RouteCallback     = "sso.callback"
	RouteLink         = "sso.link"
	RouteUnlink       = "sso.unlink"
	RouteLogout       = "sso.logout"
)

// Module wires go-auth browser SSO into the go-admin UI route surface.
type Module struct {
	handlers Handlers
}

// Handlers contains route handlers used by Module.
type Handlers struct {
	ProviderList router.HandlerFunc
	BeginLogin   router.HandlerFunc
	Callback     router.HandlerFunc
	Link         router.HandlerFunc
	Unlink       router.HandlerFunc
	Logout       router.HandlerFunc
}

// Option configures the go-admin SSO module.
type Option func(*Module)

// WithHandlers overrides one or more default handlers.
func WithHandlers(handlers Handlers) Option {
	return func(m *Module) {
		if m != nil {
			m.handlers = mergeHandlers(m.handlers, handlers)
		}
	}
}

// NewModule constructs a go-admin SSO module.
func NewModule(opts ...Option) *Module {
	m := &Module{}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
	return m
}

// Manifest describes the module for go-admin startup.
func (m *Module) Manifest() admin.ModuleManifest {
	return admin.ModuleManifest{
		ID:             ModuleID,
		NameKey:        "modules.go_auth_sso.name",
		DescriptionKey: "modules.go_auth_sso.description",
	}
}

// RouteContract declares browser SSO routes on the admin UI surface.
func (m *Module) RouteContract() routing.ModuleContract {
	return routing.ModuleContract{
		Slug: ModuleID,
		UIRoutes: map[string]string{
			RouteProviderList: "/providers",
			RouteBeginLogin:   "/login/:provider",
			RouteCallback:     "/callback/:provider",
			RouteLink:         "/link/:provider",
			RouteUnlink:       "/unlink/:provider",
			RouteLogout:       "/logout/:provider",
		},
	}
}

// Register mounts public login routes and protected account routes.
func (m *Module) Register(ctx admin.ModuleContext) error {
	if ctx.PublicRouter == nil {
		return fmt.Errorf("go-auth sso public router is required")
	}
	if ctx.ProtectedRouter == nil {
		return fmt.Errorf("go-auth sso protected router is required")
	}

	handlers := mergeHandlers(defaultHandlers(), m.handlers)
	if err := registerGet(ctx.PublicRouter, ctx, RouteProviderList, handlers.ProviderList); err != nil {
		return err
	}
	if err := registerGet(ctx.PublicRouter, ctx, RouteBeginLogin, handlers.BeginLogin); err != nil {
		return err
	}
	if err := registerGet(ctx.PublicRouter, ctx, RouteCallback, handlers.Callback); err != nil {
		return err
	}
	if err := registerPost(ctx.ProtectedRouter, ctx, RouteLink, handlers.Link); err != nil {
		return err
	}
	if err := registerPost(ctx.ProtectedRouter, ctx, RouteUnlink, handlers.Unlink); err != nil {
		return err
	}
	if err := registerPost(ctx.ProtectedRouter, ctx, RouteLogout, handlers.Logout); err != nil {
		return err
	}
	return nil
}

func registerGet(r admin.AdminRouter, ctx admin.ModuleContext, routeKey string, handler router.HandlerFunc) error {
	path := strings.TrimSpace(ctx.Routing.RoutePath(routing.SurfaceUI, routeKey))
	if path == "" {
		return fmt.Errorf("go-auth sso route %q is not resolved", routeKey)
	}
	r.Get(path, handler)
	return nil
}

func registerPost(r admin.AdminRouter, ctx admin.ModuleContext, routeKey string, handler router.HandlerFunc) error {
	path := strings.TrimSpace(ctx.Routing.RoutePath(routing.SurfaceUI, routeKey))
	if path == "" {
		return fmt.Errorf("go-auth sso route %q is not resolved", routeKey)
	}
	r.Post(path, handler)
	return nil
}

func defaultHandlers() Handlers {
	return Handlers{
		ProviderList: notConfiguredHandler,
		BeginLogin:   notConfiguredHandler,
		Callback:     notConfiguredHandler,
		Link:         notConfiguredHandler,
		Unlink:       notConfiguredHandler,
		Logout:       notConfiguredHandler,
	}
}

func mergeHandlers(base, override Handlers) Handlers {
	out := base
	if override.ProviderList != nil {
		out.ProviderList = override.ProviderList
	}
	if override.BeginLogin != nil {
		out.BeginLogin = override.BeginLogin
	}
	if override.Callback != nil {
		out.Callback = override.Callback
	}
	if override.Link != nil {
		out.Link = override.Link
	}
	if override.Unlink != nil {
		out.Unlink = override.Unlink
	}
	if override.Logout != nil {
		out.Logout = override.Logout
	}
	return out
}

func notConfiguredHandler(c router.Context) error {
	return c.Status(501).JSON(501, map[string]string{"error": "go-auth sso handler is not configured"})
}

var (
	_ admin.Module                = (*Module)(nil)
	_ admin.RouteContractProvider = (*Module)(nil)
)
