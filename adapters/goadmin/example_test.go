package goadmin

import (
	"context"
	"fmt"

	"github.com/goliatone/go-admin/admin"
	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
)

func ExampleSetupSSO() {
	adm, _ := admin.New(admin.Config{}, admin.Dependencies{})
	authCfg := exampleAuthConfig{}
	auther := auth.NewAuthenticator(exampleIdentityProvider{}, authCfg)

	result, err := SetupSSO(QuickstartConfig{
		Admin:      adm,
		AuthConfig: authCfg,
		Auther:     auther,
		Browser:    exampleBrowserFlow{},
		ProviderConfigs: []oidc.ProviderConfig{{
			Key:               "auth0",
			Issuer:            "https://tenant.us.auth0.com/",
			ClientID:          "go-auth-admin",
			RedirectURL:       "https://app.example.com/admin/sso/callback/auth0",
			Audience:          []string{"https://api.example.com"},
			AllowedAlgorithms: []string{"RS256"},
			Display:           oidc.ProviderDisplay{Label: "Auth0", Icon: "auth0"},
		}},
		ProviderLoginURL: StaticProviderLoginURLBuilder("/admin/sso"),
		ClaimPermissions: &ClaimPermissionConfig{
			PermissionMap: map[string]string{
				"reports:publish": "admin.reports.publish",
			},
		},
		HostPermissions: func(context.Context) ([]string, error) {
			return nil, nil
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(result.ProviderEntries[0].LoginURL)
	// Output: /admin/sso/login/auth0
}

type exampleAuthConfig struct{}

func (exampleAuthConfig) GetSigningKey() string           { return "01234567890123456789012345678901" }
func (exampleAuthConfig) GetSigningMethod() string        { return "HS256" }
func (exampleAuthConfig) GetContextKey() string           { return "auth" }
func (exampleAuthConfig) GetTokenExpiration() int         { return 24 }
func (exampleAuthConfig) GetExtendedTokenDuration() int   { return 48 }
func (exampleAuthConfig) GetTokenLookup() string          { return "cookie:auth" }
func (exampleAuthConfig) GetAuthScheme() string           { return "Bearer" }
func (exampleAuthConfig) GetIssuer() string               { return "go-auth-example" }
func (exampleAuthConfig) GetAudience() []string           { return []string{"go-admin"} }
func (exampleAuthConfig) GetRejectedRouteKey() string     { return "rejected" }
func (exampleAuthConfig) GetRejectedRouteDefault() string { return "/login" }

type exampleIdentityProvider struct{}

func (exampleIdentityProvider) VerifyIdentity(context.Context, string, string) (auth.Identity, error) {
	return nil, auth.ErrIdentityNotFound
}

func (exampleIdentityProvider) FindIdentityByIdentifier(context.Context, string) (auth.Identity, error) {
	return nil, auth.ErrIdentityNotFound
}

type exampleBrowserFlow struct{}

func (exampleBrowserFlow) BeginLogin(context.Context, oidc.AuthorizationRequest) (oidc.AuthorizationResponse, error) {
	return oidc.AuthorizationResponse{}, nil
}

func (exampleBrowserFlow) CompleteCallback(context.Context, oidc.CallbackRequest) (oidc.BrowserSessionResult, error) {
	return oidc.BrowserSessionResult{}, nil
}
