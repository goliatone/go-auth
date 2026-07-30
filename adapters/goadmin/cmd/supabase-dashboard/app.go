package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/goliatone/go-admin/admin"
	"github.com/goliatone/go-admin/admin/routing"
	"github.com/goliatone/go-admin/pkg/client"
	"github.com/goliatone/go-admin/quickstart"
	auth "github.com/goliatone/go-auth"
	goadmin "github.com/goliatone/go-auth/adapters/goadmin"
	"github.com/goliatone/go-auth/provider/oidc"
	"github.com/goliatone/go-auth/provider/supabase"
	router "github.com/goliatone/go-router"
)

type application struct {
	config      runtimeConfig
	persistence persistenceRuntime
	server      serverRuntime
	testRequest func(*http.Request) (*http.Response, error)
}

type serverRuntime interface {
	Serve(string) error
	Shutdown(context.Context) error
}

func buildApplication(ctx context.Context, cfg runtimeConfig) (*application, error) {
	store, err := openPersistence(ctx, cfg.DatabaseDSN)
	if err != nil {
		return nil, err
	}
	ready := false
	defer func() {
		if !ready {
			_ = store.Close()
		}
	}()

	adminCfg := newAdminConfig()
	adm, _, err := quickstart.NewAdmin(
		adminCfg,
		quickstart.AdapterHooks{},
		quickstart.WithFeatureSet(map[string]bool{string(admin.FeatureDashboard): true}),
	)
	if err != nil {
		return nil, fmt.Errorf("construct go-admin: %w", err)
	}

	views, err := quickstart.NewViewEngine(
		client.FS(),
		quickstart.WithViewTemplateFuncs(quickstart.DefaultTemplateFuncs(
			quickstart.WithTemplateURLResolver(adm.URLs()),
			quickstart.WithTemplateBasePath(adminCfg.BasePath),
			quickstart.WithTemplateFeatureGate(adm.FeatureGate()),
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("construct go-admin view engine: %w", err)
	}
	if err := quickstart.WithDefaultDashboardRenderer(adm, views, adminCfg); err != nil {
		return nil, fmt.Errorf("register dashboard renderer: %w", err)
	}
	registerDashboard(adm, adminCfg, bunProviderIdentityCounter{db: store.DB})

	server, r := quickstart.NewFiberServer(views, adminCfg, adm, true)
	authCfg := cfg.authConfig()
	auther := auth.NewAuthenticator(auth.NewUserProvider(userTracker{users: store.Users}), authCfg)
	routeAuth, err := newRouteAuthenticator(auther, authCfg, cfg.secureCookies())
	if err != nil {
		return nil, err
	}

	providerConfig := newSupabaseProviderConfig(cfg)
	provider, err := oidc.NewProvider(ctx, providerConfig)
	if err != nil {
		return nil, fmt.Errorf("discover Supabase OIDC provider: %w", err)
	}
	linker, err := oidc.NewIdentityLinker(oidc.LinkerConfig{
		Users:       store.Users,
		Identifiers: store.Identifiers,
		BindingMode: oidc.IdentifierBindingTransactionalRequired,
		AllowSignup: true,
		DefaultRole: auth.RoleMember,
		IDStrategy:  supabase.SubjectIDStrategy(),
	})
	if err != nil {
		return nil, fmt.Errorf("construct Supabase identity linker: %w", err)
	}
	issuer, err := principalTokenIssuer(auther.TokenService(), authCfg)
	if err != nil {
		return nil, err
	}
	browser, err := oidc.NewBrowserAuthenticator(oidc.BrowserAuthenticatorConfig{
		Providers:            []*oidc.Provider{provider},
		IdentityLinker:       linker,
		PrincipalMapper:      supabase.ClaimsMapper{AllowedUserRoles: []string{"authenticated"}},
		PrincipalTokenIssuer: issuer,
		LocalClaimPolicy: oidc.LocalClaimPolicy{Allow: []oidc.LocalClaim{
			oidc.LocalClaimProvider,
			oidc.LocalClaimProviderSubject,
			oidc.LocalClaimProviderSessionID,
			oidc.LocalClaimClientID,
			oidc.LocalClaimAssuranceLevel,
			oidc.LocalClaimAssuranceMethods,
			oidc.LocalClaimAuthenticationTime,
		}},
		DefaultRedirect: "/admin/dashboard",
	})
	if err != nil {
		return nil, fmt.Errorf("construct OIDC browser flow: %w", err)
	}

	setup, err := goadmin.SetupSSO(goadmin.QuickstartConfig{
		Admin:      adm,
		AuthConfig: authCfg,
		AdminAuthConfig: &admin.AuthConfig{
			LoginPath:    "/admin/login",
			LogoutPath:   "/admin/logout",
			RedirectPath: "/admin/dashboard",
		},
		Auther:             auther,
		RouteAuthenticator: routeAuth,
		Browser:            browser,
		ProviderConfigs:    []oidc.ProviderConfig{providerConfig},
		ProviderLoginURL:   goadmin.StaticProviderLoginURLBuilder("/admin/sso"),
		HostPermissions: func(context.Context) ([]string, error) {
			return []string{admin.PermAdminDashboardView}, nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("wire go-admin SSO: %w", err)
	}

	if err := adm.Initialize(r); err != nil {
		return nil, fmt.Errorf("initialize go-admin: %w", err)
	}
	quickstart.NewStaticAssets(r, adminCfg, client.Assets())

	authUIOptions := append([]quickstart.AuthUIOption{}, setup.AuthUIOptions...)
	authUIOptions = append(authUIOptions,
		quickstart.WithAuthUIFeatureGate(adm.FeatureGate()),
		quickstart.WithAuthUILogoutAuthenticator(setup.Authenticator),
		quickstart.WithAuthUILoginRedirect("/admin/dashboard"),
		quickstart.WithAuthUILogoutRedirect("/admin/login"),
		quickstart.WithAuthUIAdminTheme(adm),
		quickstart.WithAuthUICookie(sessionCookie(cfg.secureCookies())),
	)
	if err := quickstart.RegisterAuthUIRoutes(r, adminCfg, setup.RouteAuthenticator, authUIOptions...); err != nil {
		return nil, fmt.Errorf("register go-admin auth UI: %w", err)
	}
	registerHostRoutes(r)

	ready = true
	return &application{
		config:      cfg,
		persistence: store,
		server:      server,
		testRequest: func(request *http.Request) (*http.Response, error) {
			return server.WrappedRouter().Test(request, -1)
		},
	}, nil
}

func newAdminConfig() admin.Config {
	cfg := quickstart.NewAdminConfig("/admin", "Supabase Identity Dashboard", "en")
	cfg.Routing.Modules = map[string]routing.ModuleConfig{
		goadmin.ModuleID: {
			Mount: routing.ModuleMountOverride{UIBase: "/admin/sso"},
		},
	}
	return cfg
}

func newSupabaseProviderConfig(cfg runtimeConfig) oidc.ProviderConfig {
	return oidc.ProviderConfig{
		Key:                      supabase.ProviderKey,
		Issuer:                   cfg.issuerURL(),
		DiscoveryURL:             cfg.discoveryURL(),
		ClientID:                 cfg.ClientID,
		ClientSecretValue:        cfg.ClientSecret,
		TokenEndpointAuthMethod:  cfg.TokenEndpointAuth,
		RedirectURL:              cfg.callbackURL(),
		Scopes:                   []string{"openid", "profile", "email"},
		IDTokenAudience:          append([]string{}, cfg.IDTokenAudience...),
		AccessTokenAudience:      append([]string{}, cfg.AccessTokenAudience...),
		RequireAccessTokenClaims: true,
		AllowedAlgorithms:        append([]string{}, cfg.AllowedAlgorithms...),
		AllowInsecureHTTP:        cfg.AllowInsecureLoopback,
		RequestTimeout:           10 * time.Second,
		Display: oidc.ProviderDisplay{
			Label: "Supabase",
			Icon:  "supabase",
		},
		ClaimKeys: oidc.ClaimKeys{
			ResourceRoles: []string{"__supabase_disabled_resource_roles"},
		},
	}
}

func newRouteAuthenticator(auther *auth.Auther, cfg localAuthConfig, secure bool) (*auth.RouteAuthenticator, error) {
	cookie := sessionCookie(secure)
	routeAuth, err := auth.NewHTTPAuthenticator(
		auther,
		cfg,
		auth.WithAuthCookieTemplate(cookie),
		auth.WithRedirectCookieTemplate(cookie),
	)
	if err != nil {
		return nil, fmt.Errorf("construct go-auth HTTP authenticator: %w", err)
	}
	return routeAuth, nil
}

func sessionCookie(secure bool) router.Cookie {
	return router.Cookie{
		Path:     "/",
		HTTPOnly: true,
		Secure:   secure,
		SameSite: router.CookieSameSiteLaxMode,
	}
}

func registerHostRoutes[T any](r router.Router[T]) {
	r.Get("/", func(c router.Context) error {
		return c.Redirect("/admin/dashboard", http.StatusFound)
	})
	r.Get("/admin", func(c router.Context) error {
		return c.Redirect("/admin/dashboard", http.StatusFound)
	})
	r.Get("/healthz", func(c router.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
}

func (a *application) Serve() error {
	if a == nil || a.server == nil {
		return fmt.Errorf("application server is unavailable")
	}
	slog.Info("Supabase dashboard ready",
		"url", strings.TrimRight(a.config.AppURL.String(), "/")+"/admin/login",
		"dashboard", strings.TrimRight(a.config.AppURL.String(), "/")+"/admin/dashboard",
		"callback", a.config.callbackURL(),
	)
	return a.server.Serve(a.config.Address)
}

func (a *application) Close(ctx context.Context) error {
	if a == nil {
		return nil
	}
	var errs []error
	if a.server != nil {
		errs = append(errs, a.server.Shutdown(ctx))
	}
	errs = append(errs, a.persistence.Close())
	return errors.Join(errs...)
}
