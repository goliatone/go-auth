package supabase

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	"github.com/stretchr/testify/require"
)

func validConfig() Config {
	return Config{
		ProjectURL:                "https://project.supabase.co",
		ClientID:                  "client-1",
		ClientSecret:              auth.NewSecret("client-secret"),
		TokenEndpointAuthMethod:   oidc.TokenEndpointAuthClientSecretBasic,
		CallbackURL:               "https://backoffice.example/auth/callback",
		IDTokenAudience:           []string{"client-1"},
		AccessTokenAudience:       []string{"authenticated"},
		AuthorizationUIURL:        "https://backoffice.example/oauth/authorize",
		AllowedReturnURLs:         []string{"https://client.example/callback"},
		AdminCredential:           auth.NewSecret("admin-secret"),
		PublishableKey:            auth.NewSecret("publishable-key"),
		Environment:               "test",
		ProviderSessionDeployment: auth.ProviderSessionDeploymentTest,
	}.WithDefaults()
}

func TestConfigProducesHardenedOIDCPreset(t *testing.T) {
	cfg := validConfig()
	provider, err := cfg.OIDCConfig()
	require.NoError(t, err)
	require.Equal(t, ProviderKey, provider.Key)
	require.Equal(t, "https://project.supabase.co/auth/v1", provider.Issuer)
	require.Equal(t, provider.Issuer+"/.well-known/openid-configuration", provider.DiscoveryURL)
	require.True(t, provider.RequireAccessTokenClaims)
	require.Equal(t, []string{"RS256", "ES256"}, provider.AllowedAlgorithms)
	require.Equal(t, oidc.TokenEndpointAuthClientSecretBasic, provider.TokenEndpointAuthMethod)
}

func TestLocalTokenConfigDoesNotRequireProviderSessionDeployment(t *testing.T) {
	cfg := validConfig()
	cfg.ProviderSessionDeployment = ""

	require.NoError(t, cfg.Validate())
	_, err := cfg.OIDCConfig()
	require.NoError(t, err)
	_, err = cfg.PrincipalMapper()
	require.NoError(t, err)
	_, err = NewClient(cfg, nil, nil)
	require.NoError(t, err)
}

func TestProviderSessionManagerConfigRequiresExplicitMatchingDeployment(t *testing.T) {
	cfg := validConfig()
	base := auth.ProviderSessionManagerConfig{
		Binding: auth.ProviderSessionBinding{
			Host: "backoffice.example", ApplicationID: "backoffice",
			Environment: cfg.Environment, Provider: ProviderKey,
			Issuer: cfg.Issuer, ClientID: cfg.ClientID,
		},
	}
	cfg.ProviderSessionDeployment = ""
	_, err := cfg.ProviderSessionManagerConfig(base)
	require.ErrorIs(t, err, ErrInvalidConfig)

	cfg.ProviderSessionDeployment = auth.ProviderSessionDeploymentTest
	configured, err := cfg.ProviderSessionManagerConfig(base)
	require.NoError(t, err)
	require.Equal(t, auth.ProviderSessionDeploymentTest, configured.Deployment)

	base.Binding.Environment = "different-environment"
	_, err = cfg.ProviderSessionManagerConfig(base)
	require.ErrorIs(t, err, ErrInvalidConfig)
}

func TestConfigRejectsCredentialMixingAndUnsafeURLs(t *testing.T) {
	tests := map[string]func(*Config){
		"project HTTP": func(c *Config) { c.ProjectURL = "http://project.supabase.co" },
		"callback credentials": func(c *Config) {
			c.CallbackURL = "https://user:pass@backoffice.example/callback"
		},
		"issuer mismatch":    func(c *Config) { c.Issuer = "https://other.example/auth/v1" },
		"duplicate scope":    func(c *Config) { c.Scopes = append(c.Scopes, "openid") },
		"weak algorithm":     func(c *Config) { c.AllowedAlgorithms = []string{"HS256"} },
		"credential reuse":   func(c *Config) { c.PublishableKey = c.AdminCredential },
		"management reuse":   func(c *Config) { c.ManagementCredential = c.AdminCredential },
		"open return":        func(c *Config) { c.AllowedReturnURLs = []string{"javascript:alert(1)"} },
		"public with secret": func(c *Config) { c.TokenEndpointAuthMethod = oidc.TokenEndpointAuthNone },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			mutate(&cfg)
			require.ErrorIs(t, cfg.Validate(), ErrInvalidConfig)
		})
	}
}

func TestOIDCPresetDoesNotNormalizeInvalidDuplicateInputs(t *testing.T) {
	cfg := validConfig()
	cfg.Scopes = append(cfg.Scopes, "openid")
	_, err := cfg.OIDCConfig()
	require.ErrorIs(t, err, ErrInvalidConfig)

	cfg = validConfig()
	cfg.IDTokenAudience = append(cfg.IDTokenAudience, cfg.IDTokenAudience[0])
	_, err = cfg.OIDCConfig()
	require.ErrorIs(t, err, ErrInvalidConfig)
}

func TestConfigAllowsExplicitLoopbackDevelopment(t *testing.T) {
	cfg := validConfig()
	cfg.ProjectURL = "http://127.0.0.1:54321"
	cfg.Issuer = ""
	cfg.DiscoveryURL = ""
	cfg.CallbackURL = "http://localhost:8080/auth/callback"
	cfg.AuthorizationUIURL = "http://localhost:8080/oauth/authorize"
	cfg.AllowedReturnURLs = []string{"http://127.0.0.1:3000/callback"}
	cfg.AllowInsecureLoopback = true
	cfg = cfg.WithDefaults()
	require.NoError(t, cfg.Validate())
}

func TestConfigRedactsEveryCredential(t *testing.T) {
	cfg := validConfig()
	cfg.ManagementCredential = auth.NewSecret("management-secret")
	formatted := fmt.Sprintf("%+v", cfg)
	for _, secret := range []string{"client-secret", "admin-secret", "publishable-key", "management-secret"} {
		require.NotContains(t, formatted, secret)
	}
	require.True(t, strings.Count(formatted, "[REDACTED]") >= 4)
	_, err := json.Marshal(cfg)
	require.ErrorIs(t, err, auth.ErrSecretSerialization)
}

func TestReturnURLPolicyRequiresExactMatch(t *testing.T) {
	cfg := validConfig()
	require.True(t, cfg.ReturnURLAllowed("https://client.example/callback"))
	require.False(t, cfg.ReturnURLAllowed("https://client.example/callback/extra"))
	require.False(t, cfg.ReturnURLAllowed("https://client.example/callback?next=https://evil.example"))
}
