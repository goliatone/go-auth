package goadmin

import (
	"testing"

	"github.com/goliatone/go-admin/admin"
	"github.com/goliatone/go-admin/admin/routing"
	router "github.com/goliatone/go-router"
)

func TestModuleRouteContractDeclaresBrowserSSOUIRoutes(t *testing.T) {
	contract := NewModule().RouteContract()
	if contract.Slug != ModuleID {
		t.Fatalf("slug = %q, want %q", contract.Slug, ModuleID)
	}
	for _, key := range []string{RouteProviderList, RouteBeginLogin, RouteCallback, RouteLink, RouteUnlink, RouteLogout} {
		if !routing.OwnsRouteKey(ModuleID, key) {
			t.Fatalf("route key %q is not owned by module %q", key, ModuleID)
		}
		if contract.UIRoutes[key] == "" {
			t.Fatalf("expected UI route %q in contract", key)
		}
	}
	if len(contract.APIRoutes) != 0 || len(contract.PublicAPIRoutes) != 0 {
		t.Fatalf("SSO browser routes must stay on UI surface, got api=%v public=%v", contract.APIRoutes, contract.PublicAPIRoutes)
	}
}

func TestModuleRegisterUsesPublicAndProtectedRouters(t *testing.T) {
	publicRouter := &recordingRouter{}
	protectedRouter := &recordingRouter{}
	moduleCtx := admin.ModuleContext{
		PublicRouter:    publicRouter,
		ProtectedRouter: protectedRouter,
		Routing: routing.BuildModuleContext(NewModule().RouteContract(), routing.ResolvedModule{
			Slug:        ModuleID,
			UIMountBase: "/admin/sso",
			UIGroupPath: "/admin",
		}),
	}

	if err := NewModule().Register(moduleCtx); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	assertRoute(t, publicRouter, "GET", "/admin/sso/providers")
	assertRoute(t, publicRouter, "GET", "/admin/sso/login/:provider")
	assertRoute(t, publicRouter, "GET", "/admin/sso/callback/:provider")
	assertNoRoute(t, publicRouter, "POST", "/admin/sso/link/:provider")
	assertNoRoute(t, publicRouter, "POST", "/admin/sso/unlink/:provider")
	assertNoRoute(t, publicRouter, "POST", "/admin/sso/logout/:provider")

	assertRoute(t, protectedRouter, "POST", "/admin/sso/link/:provider")
	assertRoute(t, protectedRouter, "POST", "/admin/sso/unlink/:provider")
	assertRoute(t, protectedRouter, "POST", "/admin/sso/logout/:provider")
	assertNoRoute(t, protectedRouter, "GET", "/admin/sso/login/:provider")
	assertNoRoute(t, protectedRouter, "GET", "/admin/sso/callback/:provider")
}

func TestModuleRegisterRequiresResolvedRouteContract(t *testing.T) {
	err := NewModule().Register(admin.ModuleContext{
		PublicRouter:    &recordingRouter{},
		ProtectedRouter: &recordingRouter{},
	})
	if err == nil {
		t.Fatal("expected unresolved route contract error")
	}
}

func assertRoute(t *testing.T, r *recordingRouter, method, path string) {
	t.Helper()
	if !r.has(method, path) {
		t.Fatalf("expected %s %s registered, got %#v", method, path, r.routes)
	}
}

func assertNoRoute(t *testing.T, r *recordingRouter, method, path string) {
	t.Helper()
	if r.has(method, path) {
		t.Fatalf("did not expect %s %s registered on router %#v", method, path, r.routes)
	}
}

type recordedRoute struct {
	method string
	path   string
}

type recordingRouter struct {
	routes []recordedRoute
}

func (r *recordingRouter) has(method, path string) bool {
	for _, route := range r.routes {
		if route.method == method && route.path == path {
			return true
		}
	}
	return false
}

func (r *recordingRouter) Handle(method router.HTTPMethod, path string, handler router.HandlerFunc, mw ...router.MiddlewareFunc) router.RouteInfo {
	r.routes = append(r.routes, recordedRoute{method: string(method), path: path})
	return nil
}

func (r *recordingRouter) Get(path string, handler router.HandlerFunc, mw ...router.MiddlewareFunc) router.RouteInfo {
	return r.Handle(router.GET, path, handler, mw...)
}

func (r *recordingRouter) Post(path string, handler router.HandlerFunc, mw ...router.MiddlewareFunc) router.RouteInfo {
	return r.Handle(router.POST, path, handler, mw...)
}

func (r *recordingRouter) Put(path string, handler router.HandlerFunc, mw ...router.MiddlewareFunc) router.RouteInfo {
	return r.Handle(router.PUT, path, handler, mw...)
}

func (r *recordingRouter) Delete(path string, handler router.HandlerFunc, mw ...router.MiddlewareFunc) router.RouteInfo {
	return r.Handle(router.DELETE, path, handler, mw...)
}

func (r *recordingRouter) Patch(path string, handler router.HandlerFunc, mw ...router.MiddlewareFunc) router.RouteInfo {
	return r.Handle(router.PATCH, path, handler, mw...)
}

func (r *recordingRouter) Head(path string, handler router.HandlerFunc, mw ...router.MiddlewareFunc) router.RouteInfo {
	return r.Handle(router.HEAD, path, handler, mw...)
}
