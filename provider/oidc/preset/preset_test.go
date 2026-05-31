package preset

import (
	"testing"

	"github.com/goliatone/go-auth/provider/oidc"
)

func TestPresetsApplyProviderConventions(t *testing.T) {
	cfg := Apply(oidc.ProviderConfig{Key: "auth0"}, Auth0("tenant.auth0.com"))
	if cfg.Issuer != "https://tenant.auth0.com/" {
		t.Fatalf("Auth0 issuer = %q", cfg.Issuer)
	}
	if cfg.Display.Label != "Auth0" || cfg.Display.Icon != "auth0" {
		t.Fatalf("Auth0 display not set: %+v", cfg.Display)
	}
	if len(cfg.ClaimKeys.Permissions) == 0 || cfg.ClaimKeys.Permissions[0] != "permissions" {
		t.Fatalf("Auth0 permissions claim keys not set: %+v", cfg.ClaimKeys)
	}

	azure := Apply(oidc.ProviderConfig{Key: "azure"}, AzureAD("tenant-id"))
	if azure.Issuer != "https://login.microsoftonline.com/tenant-id/v2.0" {
		t.Fatalf("Azure issuer = %q", azure.Issuer)
	}
	if len(azure.ClaimKeys.TenantID) == 0 || azure.ClaimKeys.TenantID[0] != "tid" {
		t.Fatalf("Azure tenant claim keys not set: %+v", azure.ClaimKeys)
	}
}

func TestPresetsPreserveExplicitValues(t *testing.T) {
	cfg := Apply(oidc.ProviderConfig{
		Key:    "okta",
		Issuer: "https://custom.example/oauth2/default",
		Scopes: []string{"openid", "custom"},
		Display: oidc.ProviderDisplay{
			Label: "Company SSO",
			Icon:  "company",
		},
		ClaimKeys: oidc.ClaimKeys{Groups: []string{"custom_groups"}},
	}, Okta("https://dev.example"))

	if cfg.Issuer != "https://custom.example/oauth2/default" {
		t.Fatalf("issuer was overwritten: %q", cfg.Issuer)
	}
	if len(cfg.Scopes) != 2 || cfg.Scopes[1] != "custom" {
		t.Fatalf("scopes were overwritten: %+v", cfg.Scopes)
	}
	if cfg.Display.Label != "Company SSO" || cfg.Display.Icon != "company" {
		t.Fatalf("display was overwritten: %+v", cfg.Display)
	}
	if len(cfg.ClaimKeys.Groups) != 1 || cfg.ClaimKeys.Groups[0] != "custom_groups" {
		t.Fatalf("claim keys were overwritten: %+v", cfg.ClaimKeys)
	}
}
