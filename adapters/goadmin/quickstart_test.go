package goadmin

import (
	"context"
	"strings"
	"testing"

	"github.com/goliatone/go-admin/admin"
	"github.com/goliatone/go-admin/quickstart"
	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	router "github.com/goliatone/go-router"
)

func TestResolveProviderEntriesRejectsDuplicateKeys(t *testing.T) {
	_, err := resolveProviderEntries(nil, []oidc.ProviderInfo{
		{Key: "auth0", Label: "Auth0", LoginURL: "/sso/login/auth0"},
		{Key: "AUTH0", Label: "Auth0 duplicate", LoginURL: "/sso/login/auth0-alt"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate key error, got %v", err)
	}
}

func TestResolveProviderEntriesRejectsUnsafeLoginURL(t *testing.T) {
	_, err := resolveProviderEntries(nil, []oidc.ProviderInfo{
		{Key: "auth0", Label: "Auth0", LoginURL: "https://evil.example/login"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "same-origin") {
		t.Fatalf("expected unsafe login URL error, got %v", err)
	}
}

func TestResolveProviderEntriesRejectsAllDisabledStaticEntries(t *testing.T) {
	_, err := resolveProviderEntries(nil, []oidc.ProviderInfo{
		{Key: "auth0", Label: "Auth0", LoginURL: "/sso/login/auth0", DisabledReason: "maintenance"},
		{Key: "okta", Label: "Okta", LoginURL: "/sso/login/okta", DisabledReason: "not available"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "at least one SSO provider must be enabled") {
		t.Fatalf("expected enabled-provider error, got %v", err)
	}
}

func TestResolveProviderEntriesAllowsMixedEnabledAndDisabledStaticEntries(t *testing.T) {
	entries, err := resolveProviderEntries(nil, []oidc.ProviderInfo{
		{Key: "auth0", Label: "Auth0", LoginURL: "/sso/login/auth0"},
		{Key: "okta", Label: "Okta", LoginURL: "/sso/login/okta", DisabledReason: "not available"},
	}, nil)
	if err != nil {
		t.Fatalf("resolveProviderEntries: %v", err)
	}
	if len(entries) != 2 || entries[0].DisabledReason != "" || entries[1].DisabledReason == "" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestResolveProviderEntriesRejectsPartialProviderConfig(t *testing.T) {
	_, err := resolveProviderEntries([]oidc.ProviderConfig{{Key: "auth0", RedirectURL: "http://app.example/callback"}}, nil, StaticProviderLoginURLBuilder("/admin/sso"))
	if err == nil || !strings.Contains(err.Error(), "client ID") {
		t.Fatalf("expected partial provider config error, got %v", err)
	}
}

func TestResolveProviderEntriesRequiresLoginURLBuilderForProviderConfigs(t *testing.T) {
	_, err := resolveProviderEntries([]oidc.ProviderConfig{{
		Key:         "auth0",
		Issuer:      "https://idp.example/",
		ClientID:    "client-id",
		RedirectURL: "https://app.example/admin/sso/callback/auth0",
	}}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "login URL builder") {
		t.Fatalf("expected login URL builder error, got %v", err)
	}
}

func TestResolveProviderEntriesBuildsRouteAwareLoginURLs(t *testing.T) {
	entries, err := resolveProviderEntries([]oidc.ProviderConfig{{
		Key:         "auth0",
		Issuer:      "https://idp.example/",
		ClientID:    "client-id",
		RedirectURL: "https://app.example/admin/sso/callback/auth0",
		Display:     oidc.ProviderDisplay{Label: "Auth0"},
	}}, nil, StaticProviderLoginURLBuilder("/admin/sso"))
	if err != nil {
		t.Fatalf("resolveProviderEntries: %v", err)
	}
	if len(entries) != 1 || entries[0].LoginURL != "/admin/sso/login/auth0" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestSetupSSOReturnsWiredComponentsAndAuthUIOptions(t *testing.T) {
	adm, err := admin.New(admin.Config{}, admin.Dependencies{})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	cfg := testAuthConfig{}
	auther := auth.NewAuthenticator(fakeIdentityProvider{}, cfg)
	var registeredRouteAuth *auth.RouteAuthenticator
	var registeredOptions []quickstart.AuthUIOption

	result, err := SetupSSO(QuickstartConfig{
		Admin:        adm,
		AuthConfig:   cfg,
		Auther:       auther,
		Browser:      stubBrowserFlow{},
		ActivitySink: &recordingActivitySink{},
		ProviderEntries: []oidc.ProviderInfo{
			{Key: "auth0", Label: "Auth0", LoginURL: "/sso/login/auth0"},
		},
		RegisterAuthUI: func(routeAuth *auth.RouteAuthenticator, opts ...quickstart.AuthUIOption) error {
			registeredRouteAuth = routeAuth
			registeredOptions = append([]quickstart.AuthUIOption{}, opts...)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("SetupSSO: %v", err)
	}
	if result.Authenticator == nil || result.Authorizer == nil || result.Module == nil || result.RouteAuthenticator == nil {
		t.Fatalf("expected constructed components, got %#v", result)
	}
	if registeredRouteAuth != result.RouteAuthenticator {
		t.Fatalf("auth UI route authenticator was not the constructed route authenticator")
	}
	if len(registeredOptions) == 0 || len(result.AuthUIOptions) == 0 {
		t.Fatalf("expected auth UI options to include SSO provider context")
	}
	viewCtx := router.ViewContext{}
	viewCtx = SSOAuthUIViewContextBuilder(result.ProviderEntries)(viewCtx, nil)
	providers, ok := viewCtx["sso_providers"].([]oidc.ProviderInfo)
	if !ok || len(providers) != 1 || providers[0].Key != "auth0" {
		t.Fatalf("unexpected SSO view context: %#v", viewCtx)
	}
	if viewCtx["sso_enabled"] != true || viewCtx["sso_provider_count"] != 1 {
		t.Fatalf("unexpected SSO enabled flags: %#v", viewCtx)
	}
}

func TestSetupSSOWiresComposedPermissionResolver(t *testing.T) {
	adm, err := admin.New(admin.Config{}, admin.Dependencies{})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	cfg := testAuthConfig{}
	result, err := SetupSSO(QuickstartConfig{
		Admin:      adm,
		AuthConfig: cfg,
		Auther:     auth.NewAuthenticator(fakeIdentityProvider{}, cfg),
		Browser:    stubBrowserFlow{},
		ProviderEntries: []oidc.ProviderInfo{
			{Key: "auth0", Label: "Auth0", LoginURL: "/sso/login/auth0"},
		},
		ClaimPermissions: &ClaimPermissionConfig{
			PermissionMap: map[string]string{"reports:publish": "admin.reports.publish"},
		},
		HostPermissions: func(context.Context) ([]string, error) {
			return []string{"admin.billing.approve"}, nil
		},
	})
	if err != nil {
		t.Fatalf("SetupSSO: %v", err)
	}
	ctx := auth.WithClaimsContext(context.Background(), &auth.JWTClaims{
		UID:      "user-1",
		Metadata: map[string]any{"permissions": []string{"reports:publish"}},
	})
	if !result.Authorizer.Can(ctx, "admin.reports.publish", "") {
		t.Fatal("expected IdP mapped permission")
	}
	if !result.Authorizer.Can(ctx, "admin.billing.approve", "") {
		t.Fatal("expected host local permission")
	}
}

type testAuthConfig struct{}

func (testAuthConfig) GetSigningKey() string           { return "01234567890123456789012345678901" }
func (testAuthConfig) GetSigningMethod() string        { return "HS256" }
func (testAuthConfig) GetContextKey() string           { return "auth" }
func (testAuthConfig) GetTokenExpiration() int         { return 24 }
func (testAuthConfig) GetExtendedTokenDuration() int   { return 48 }
func (testAuthConfig) GetTokenLookup() string          { return "cookie:auth" }
func (testAuthConfig) GetAuthScheme() string           { return "Bearer" }
func (testAuthConfig) GetIssuer() string               { return "go-auth-test" }
func (testAuthConfig) GetAudience() []string           { return []string{"go-admin"} }
func (testAuthConfig) GetRejectedRouteKey() string     { return "rejected" }
func (testAuthConfig) GetRejectedRouteDefault() string { return "/login" }

type fakeIdentityProvider struct{}

func (fakeIdentityProvider) VerifyIdentity(context.Context, string, string) (auth.Identity, error) {
	return nil, auth.ErrIdentityNotFound
}

func (fakeIdentityProvider) FindIdentityByIdentifier(context.Context, string) (auth.Identity, error) {
	return nil, auth.ErrIdentityNotFound
}
