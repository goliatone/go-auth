package preset

import (
	"fmt"
	"strings"

	"github.com/goliatone/go-auth/provider/oidc"
)

type Preset func(oidc.ProviderConfig) oidc.ProviderConfig

func Auth0(domain string) Preset {
	return func(cfg oidc.ProviderConfig) oidc.ProviderConfig {
		domain = strings.TrimSpace(domain)
		if domain != "" && !strings.HasPrefix(domain, "https://") {
			domain = "https://" + domain
		}
		domain = strings.TrimRight(domain, "/")
		cfg.Issuer = firstNonEmpty(cfg.Issuer, domain+"/")
		cfg.Scopes = firstScopes(cfg.Scopes, []string{"openid", "profile", "email"})
		cfg.Display = defaultDisplay(cfg.Display, "Auth0", "auth0")
		cfg.ClaimKeys.OrganizationID = firstKeys(cfg.ClaimKeys.OrganizationID, []string{"organization_id", "org_id"})
		cfg.ClaimKeys.Permissions = firstKeys(cfg.ClaimKeys.Permissions, []string{"permissions", "scope"})
		return cfg
	}
}

func GoogleWorkspace() Preset {
	return func(cfg oidc.ProviderConfig) oidc.ProviderConfig {
		cfg.Issuer = firstNonEmpty(cfg.Issuer, "https://accounts.google.com")
		cfg.Scopes = firstScopes(cfg.Scopes, []string{"openid", "profile", "email"})
		cfg.Display = defaultDisplay(cfg.Display, "Google", "google")
		cfg.ClaimKeys.OrganizationID = firstKeys(cfg.ClaimKeys.OrganizationID, []string{"hd", "organization_id"})
		return cfg
	}
}

func Okta(orgURL string) Preset {
	return func(cfg oidc.ProviderConfig) oidc.ProviderConfig {
		orgURL = strings.TrimRight(strings.TrimSpace(orgURL), "/")
		cfg.Issuer = firstNonEmpty(cfg.Issuer, orgURL)
		cfg.Scopes = firstScopes(cfg.Scopes, []string{"openid", "profile", "email", "groups"})
		cfg.Display = defaultDisplay(cfg.Display, "Okta", "okta")
		cfg.ClaimKeys.Groups = firstKeys(cfg.ClaimKeys.Groups, []string{"groups"})
		return cfg
	}
}

func AzureAD(tenantID string) Preset {
	return func(cfg oidc.ProviderConfig) oidc.ProviderConfig {
		tenantID = strings.TrimSpace(tenantID)
		if tenantID == "" {
			tenantID = "common"
		}
		cfg.Issuer = firstNonEmpty(cfg.Issuer, fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID))
		cfg.Scopes = firstScopes(cfg.Scopes, []string{"openid", "profile", "email"})
		cfg.Display = defaultDisplay(cfg.Display, "Microsoft", "microsoft")
		cfg.ClaimKeys.TenantID = firstKeys(cfg.ClaimKeys.TenantID, []string{"tid", "tenant_id"})
		cfg.ClaimKeys.Roles = firstKeys(cfg.ClaimKeys.Roles, []string{"roles"})
		return cfg
	}
}

func Apply(cfg oidc.ProviderConfig, presets ...Preset) oidc.ProviderConfig {
	for _, preset := range presets {
		if preset != nil {
			cfg = preset(cfg)
		}
	}
	return cfg
}

func firstNonEmpty(current, fallback string) string {
	if strings.TrimSpace(current) != "" {
		return current
	}
	return fallback
}

func firstScopes(current, fallback []string) []string {
	if len(current) > 0 {
		return current
	}
	return append([]string(nil), fallback...)
}

func firstKeys(current, fallback []string) []string {
	if len(current) > 0 {
		return current
	}
	return append([]string(nil), fallback...)
}

func defaultDisplay(current oidc.ProviderDisplay, label, icon string) oidc.ProviderDisplay {
	if strings.TrimSpace(current.Label) == "" {
		current.Label = label
	}
	if strings.TrimSpace(current.Icon) == "" {
		current.Icon = icon
	}
	return current
}
