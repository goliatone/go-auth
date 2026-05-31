package goadmin

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/goliatone/go-admin/admin"
	"github.com/goliatone/go-admin/quickstart"
	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	router "github.com/goliatone/go-router"
)

// RegisterAuthUIFunc lets hosts opt into go-admin auth UI registration while
// keeping this adapter independent from a concrete router type.
type RegisterAuthUIFunc func(routeAuth *auth.RouteAuthenticator, opts ...quickstart.AuthUIOption) error

// ProviderLoginURLBuilder builds the begin-login URL exposed to templates.
type ProviderLoginURLBuilder func(providerKey string) string

// QuickstartConfig captures the SSO-aware go-admin wiring.
type QuickstartConfig struct {
	Admin                *admin.Admin
	AuthConfig           auth.Config
	AdminAuthConfig      *admin.AuthConfig
	IdentityProvider     auth.IdentityProvider
	Auther               *auth.Auther
	RouteAuthenticator   *auth.RouteAuthenticator
	Browser              BrowserFlow
	ProviderConfigs      []oidc.ProviderConfig
	ProviderEntries      []oidc.ProviderInfo
	ProviderLoginURL     ProviderLoginURLBuilder
	TokenValidators      []auth.TokenValidator
	ActivitySink         auth.ActivitySink
	ManualLinker         ManualLinker
	ManualLinkVerifier   ManualLinkProofVerifier
	ManualUnlinker       ManualUnlinker
	LogoutRedirect       LogoutRedirectResolver
	ClaimPermissions     *ClaimPermissionConfig
	HostPermissions      PermissionResolverFunc
	AuthorizerConfig     admin.GoAuthAuthorizerConfig
	AuthenticatorOptions []admin.GoAuthAuthenticatorOption
	RegisterAuthUI       RegisterAuthUIFunc
	AuthUIOptions        []quickstart.AuthUIOption
	ExtendedCookies      bool
}

// QuickstartResult returns the constructed pieces for host customization.
type QuickstartResult struct {
	Auther             *auth.Auther
	RouteAuthenticator *auth.RouteAuthenticator
	Authenticator      *admin.GoAuthAuthenticator
	Authorizer         *admin.GoAuthAuthorizer
	Module             *Module
	ProviderEntries    []oidc.ProviderInfo
	AuthUIOptions      []quickstart.AuthUIOption
}

// SetupSSO wires go-auth SSO into go-admin before adm.Initialize is called.
func SetupSSO(cfg QuickstartConfig) (QuickstartResult, error) {
	if cfg.Admin == nil {
		return QuickstartResult{}, fmt.Errorf("go-admin instance is required")
	}
	if cfg.AuthConfig == nil {
		return QuickstartResult{}, fmt.Errorf("go-auth config is required")
	}
	if cfg.Browser == nil {
		return QuickstartResult{}, fmt.Errorf("go-auth sso browser authenticator is required")
	}

	entries, err := resolveProviderEntries(cfg.ProviderConfigs, cfg.ProviderEntries, cfg.ProviderLoginURL)
	if err != nil {
		return QuickstartResult{}, err
	}

	auther := cfg.Auther
	if auther == nil {
		if cfg.IdentityProvider == nil {
			return QuickstartResult{}, fmt.Errorf("go-auth identity provider is required when auther is not supplied")
		}
		auther = auth.NewAuthenticator(cfg.IdentityProvider, cfg.AuthConfig)
	}
	if cfg.ActivitySink != nil {
		auther.WithActivitySink(cfg.ActivitySink)
	}
	if len(cfg.TokenValidators) > 0 {
		validators := append([]auth.TokenValidator{}, cfg.TokenValidators...)
		if auther.TokenService() != nil {
			validators = append(validators, auther.TokenService())
		}
		auther.WithTokenValidator(auth.NewMultiTokenValidator(validators...))
	}

	routeAuth := cfg.RouteAuthenticator
	if routeAuth == nil {
		routeAuth, err = auth.NewHTTPAuthenticator(auther, cfg.AuthConfig)
		if err != nil {
			return QuickstartResult{}, fmt.Errorf("create go-auth route authenticator: %w", err)
		}
	}

	authenticator := admin.NewGoAuthAuthenticator(routeAuth, cfg.AuthConfig, cfg.AuthenticatorOptions...)
	if authenticator == nil {
		return QuickstartResult{}, fmt.Errorf("create go-admin authenticator")
	}
	cfg.Admin.WithAuth(authenticator, cfg.AdminAuthConfig)

	authorizerConfig := cfg.AuthorizerConfig
	resolvers := []PermissionResolverFunc{}
	if cfg.ClaimPermissions != nil {
		resolvers = append(resolvers, ClaimPermissionResolverFunc(*cfg.ClaimPermissions))
	}
	if cfg.HostPermissions != nil {
		resolvers = append(resolvers, cfg.HostPermissions)
	}
	if authorizerConfig.ResolvePermissions != nil {
		resolvers = append(resolvers, authorizerConfig.ResolvePermissions)
	}
	if len(resolvers) > 0 {
		authorizerConfig.ResolvePermissions = ComposePermissionResolvers(resolvers...)
	}
	authorizer := admin.NewGoAuthAuthorizer(authorizerConfig)
	cfg.Admin.WithAuthorizer(authorizer)

	handlers, err := NewHandlers(HandlerConfig{
		Providers:              entries,
		Browser:                cfg.Browser,
		RouteAuthenticator:     routeAuth,
		ActivitySink:           cfg.ActivitySink,
		ManualLinker:           cfg.ManualLinker,
		ManualLinkVerifier:     cfg.ManualLinkVerifier,
		ManualUnlinker:         cfg.ManualUnlinker,
		LogoutRedirect:         cfg.LogoutRedirect,
		ExtendedSessionCookies: cfg.ExtendedCookies,
	})
	if err != nil {
		return QuickstartResult{}, err
	}
	module := NewModule(WithHandlers(handlers))
	if err := cfg.Admin.RegisterModule(module); err != nil {
		return QuickstartResult{}, fmt.Errorf("register go-auth sso module: %w", err)
	}

	authUIOptions := append([]quickstart.AuthUIOption{}, cfg.AuthUIOptions...)
	authUIOptions = append(authUIOptions, quickstart.WithAuthUIViewContextBuilder(SSOAuthUIViewContextBuilder(entries)))
	if cfg.RegisterAuthUI != nil {
		if err := cfg.RegisterAuthUI(routeAuth, authUIOptions...); err != nil {
			return QuickstartResult{}, fmt.Errorf("register go-admin auth UI routes: %w", err)
		}
	}

	return QuickstartResult{
		Auther:             auther,
		RouteAuthenticator: routeAuth,
		Authenticator:      authenticator,
		Authorizer:         authorizer,
		Module:             module,
		ProviderEntries:    entries,
		AuthUIOptions:      authUIOptions,
	}, nil
}

// SSOAuthUIViewContextBuilder injects provider entries for go-admin login templates.
func SSOAuthUIViewContextBuilder(entries []oidc.ProviderInfo) quickstart.AuthUIViewContextBuilder {
	providers := sanitizeProviderInfo(entries)
	return func(ctx router.ViewContext, _ router.Context) router.ViewContext {
		if ctx == nil {
			ctx = router.ViewContext{}
		}
		ctx["sso_providers"] = append([]oidc.ProviderInfo{}, providers...)
		ctx["sso_enabled"] = len(providers) > 0
		ctx["sso_provider_count"] = len(providers)
		return ctx
	}
}

// StaticProviderLoginURLBuilder returns a simple builder for known SSO mount bases.
func StaticProviderLoginURLBuilder(basePath string) ProviderLoginURLBuilder {
	basePath = strings.TrimRight(strings.TrimSpace(basePath), "/")
	return func(providerKey string) string {
		key := strings.TrimSpace(providerKey)
		if key == "" {
			return ""
		}
		if basePath == "" {
			basePath = "/"
		}
		return strings.TrimRight(basePath, "/") + "/login/" + url.PathEscape(key)
	}
}

func resolveProviderEntries(configs []oidc.ProviderConfig, entries []oidc.ProviderInfo, loginURL ProviderLoginURLBuilder) ([]oidc.ProviderInfo, error) {
	resolved := make([]oidc.ProviderInfo, 0, len(entries)+len(configs))
	seen := map[string]struct{}{}
	for _, entry := range entries {
		key := strings.ToLower(strings.TrimSpace(entry.Key))
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate SSO provider key %q", entry.Key)
		}
		seen[key] = struct{}{}
		if err := validateProviderLoginURL(entry.LoginURL); err != nil {
			return nil, fmt.Errorf("provider %q login URL: %w", entry.Key, err)
		}
		resolved = append(resolved, sanitizeProviderInfo([]oidc.ProviderInfo{entry})...)
	}

	for _, provider := range configs {
		entry, err := providerEntryFromConfig(provider, loginURL)
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(strings.TrimSpace(entry.Key))
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate SSO provider key %q", entry.Key)
		}
		seen[key] = struct{}{}
		resolved = append(resolved, entry)
	}
	if enabled := enabledProviderCount(resolved); len(resolved) > 0 && enabled == 0 {
		return nil, fmt.Errorf("at least one SSO provider must be enabled")
	}
	return resolved, nil
}

func providerEntryFromConfig(provider oidc.ProviderConfig, loginURL ProviderLoginURLBuilder) (oidc.ProviderInfo, error) {
	key := strings.TrimSpace(provider.Key)
	if key == "" {
		return oidc.ProviderInfo{}, fmt.Errorf("provider key is required")
	}
	if strings.TrimSpace(provider.ClientID) == "" {
		return oidc.ProviderInfo{}, fmt.Errorf("provider %q client ID is required", key)
	}
	if strings.TrimSpace(provider.Issuer) == "" && strings.TrimSpace(provider.DiscoveryURL) == "" {
		return oidc.ProviderInfo{}, fmt.Errorf("provider %q issuer or discovery URL is required", key)
	}
	if err := validateAbsoluteURL(provider.RedirectURL); err != nil {
		return oidc.ProviderInfo{}, fmt.Errorf("provider %q redirect URL: %w", key, err)
	}
	if loginURL == nil {
		return oidc.ProviderInfo{}, fmt.Errorf("provider %q login URL builder is required", key)
	}
	loginPath := strings.TrimSpace(loginURL(key))
	if err := validateProviderLoginURL(loginPath); err != nil {
		return oidc.ProviderInfo{}, fmt.Errorf("provider %q login URL: %w", key, err)
	}
	label := strings.TrimSpace(provider.Display.Label)
	if label == "" {
		label = key
	}
	return oidc.ProviderInfo{
		Key:            key,
		Label:          label,
		LoginURL:       loginPath,
		Icon:           strings.TrimSpace(provider.Display.Icon),
		IconURL:        strings.TrimSpace(provider.Display.IconURL),
		DisabledReason: strings.TrimSpace(provider.Display.DisabledReason),
	}, nil
}

func validateProviderLoginURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("is required")
	}
	if strings.Contains(raw, "\\") {
		return fmt.Errorf("contains unsafe path separator")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.IsAbs() {
		return fmt.Errorf("must be a same-origin relative path")
	}
	if strings.HasPrefix(raw, "//") || !strings.HasPrefix(parsed.Path, "/") {
		return fmt.Errorf("must be a same-origin relative path")
	}
	return nil
}

func validateAbsoluteURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("must be absolute")
	}
	return nil
}

func enabledProviderCount(providers []oidc.ProviderInfo) int {
	count := 0
	for _, provider := range providers {
		if strings.TrimSpace(provider.DisabledReason) == "" {
			count++
		}
	}
	return count
}
