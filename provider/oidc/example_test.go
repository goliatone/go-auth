package oidc_test

import (
	"fmt"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	"github.com/goliatone/go-auth/provider/oidc/preset"
)

func ExampleProviderConfig_genericOIDC() {
	provider := oidc.ProviderConfig{
		Key:               "enterprise",
		Issuer:            "https://idp.example.com/",
		ClientID:          "go-auth-admin",
		ClientSecret:      "use-secret-manager",
		RedirectURL:       "https://app.example.com/admin/sso/callback/enterprise",
		Scopes:            []string{"openid", "profile", "email", "groups"},
		Audience:          []string{"go-auth-admin"},
		AllowedAlgorithms: []string{"RS256"},
		Display: oidc.ProviderDisplay{
			Label: "Enterprise SSO",
			Icon:  "building",
		},
	}

	_ = oidc.Config{
		Providers:              []oidc.ProviderConfig{provider},
		DefaultRedirect:        "/admin",
		AllowedRedirectOrigins: []string{"https://app.example.com"},
		AllowSignup:            true,
		EmailFallback: oidc.EmailFallbackPolicy{
			Enabled:              true,
			RequireVerifiedEmail: true,
		},
	}

	fmt.Println(provider.Scopes[0])
	// Output: openid
}

func ExampleProviderConfig_auth0AsOIDC() {
	provider := preset.Apply(oidc.ProviderConfig{
		Key:               "auth0",
		ClientID:          "go-auth-admin",
		ClientSecret:      "use-secret-manager",
		RedirectURL:       "https://app.example.com/admin/sso/callback/auth0",
		Audience:          []string{"https://api.example.com"},
		AllowedAlgorithms: []string{"RS256"},
	}, preset.Auth0("tenant.us.auth0.com"))

	fmt.Println(provider.Issuer)
	// Output: https://tenant.us.auth0.com/
}

func ExampleNewMultiTokenValidator_externalAndLocal() {
	externalOIDC := auth.TokenValidatorFunc(func(token string) (auth.AuthClaims, error) {
		return nil, auth.ErrTokenMalformed
	})
	localJWT := auth.TokenValidatorFunc(func(token string) (auth.AuthClaims, error) {
		return nil, auth.ErrTokenMalformed
	})

	validator := auth.NewMultiTokenValidator(externalOIDC, localJWT)
	_, err := validator.Validate("not-a-jwt")

	fmt.Println(auth.IsMalformedError(err))
	// Output: true
}
