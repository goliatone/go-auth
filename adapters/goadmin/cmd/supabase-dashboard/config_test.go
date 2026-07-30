package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/goliatone/go-auth/provider/oidc"
)

func TestLoadRuntimeConfigBuildsExactSupabaseRoutes(t *testing.T) {
	env := map[string]string{
		"SUPABASE_PROJECT_URL":              "https://project-ref.supabase.co",
		"SUPABASE_OAUTH_CLIENT_ID":          "dashboard-client",
		"SUPABASE_OAUTH_CLIENT_SECRET":      "client-secret-canary",
		"SUPABASE_ALLOW_INSECURE_LOOPBACK":  "true",
		"GOAUTH_SIGNING_KEY":                strings.Repeat("k", 32),
		"APP_URL":                           "http://127.0.0.1:9090",
		"SUPABASE_ACCESS_TOKEN_AUDIENCE":    "authenticated,api",
		"SUPABASE_OAUTH_CLIENT_AUTH_METHOD": "client_secret_basic",
	}
	cfg, err := loadRuntimeConfigFrom(func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("loadRuntimeConfigFrom: %v", err)
	}
	if got, want := cfg.callbackURL(), "http://127.0.0.1:9090/admin/sso/callback/supabase"; got != want {
		t.Fatalf("callback URL = %q, want %q", got, want)
	}
	if got, want := cfg.discoveryURL(), "https://project-ref.supabase.co/auth/v1/.well-known/openid-configuration"; got != want {
		t.Fatalf("discovery URL = %q, want %q", got, want)
	}
	if cfg.TokenEndpointAuth != oidc.TokenEndpointAuthClientSecretBasic {
		t.Fatalf("client auth method = %q", cfg.TokenEndpointAuth)
	}
	if len(cfg.AccessTokenAudience) != 2 {
		t.Fatalf("access audiences = %#v", cfg.AccessTokenAudience)
	}

	formatted := fmt.Sprintf("%+v", cfg)
	for _, secret := range []string{"client-secret-canary", strings.Repeat("k", 32)} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("formatted config exposed a secret: %s", formatted)
		}
	}
}

func TestLoadRuntimeConfigRejectsUnsafeOrIncompleteInput(t *testing.T) {
	base := map[string]string{
		"SUPABASE_PROJECT_URL":             "https://project-ref.supabase.co",
		"SUPABASE_OAUTH_CLIENT_ID":         "dashboard-client",
		"SUPABASE_OAUTH_CLIENT_SECRET":     "client-secret",
		"SUPABASE_ALLOW_INSECURE_LOOPBACK": "true",
		"GOAUTH_SIGNING_KEY":               strings.Repeat("k", 32),
	}
	tests := []struct {
		name   string
		mutate func(map[string]string)
		want   string
	}{
		{
			name: "loopback callback without explicit opt in",
			mutate: func(env map[string]string) {
				env["SUPABASE_ALLOW_INSECURE_LOOPBACK"] = ""
			},
			want: "APP_URL",
		},
		{
			name: "non HTTPS provider",
			mutate: func(env map[string]string) {
				env["SUPABASE_PROJECT_URL"] = "http://project.example"
			},
			want: "HTTP is allowed only",
		},
		{
			name: "short local signing key",
			mutate: func(env map[string]string) {
				env["GOAUTH_SIGNING_KEY"] = "short"
			},
			want: "at least 32 bytes",
		},
		{
			name: "missing confidential secret",
			mutate: func(env map[string]string) {
				env["SUPABASE_OAUTH_CLIENT_SECRET"] = ""
			},
			want: "required for confidential clients",
		},
		{
			name: "public client with secret",
			mutate: func(env map[string]string) {
				env["SUPABASE_OAUTH_CLIENT_AUTH_METHOD"] = "none"
			},
			want: "must be empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := map[string]string{}
			for key, value := range base {
				env[key] = value
			}
			test.mutate(env)
			_, err := loadRuntimeConfigFrom(func(key string) string { return env[key] })
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestNewAdminConfigMountsSSOAtDocumentedPath(t *testing.T) {
	cfg := newAdminConfig()
	module, ok := cfg.Routing.Modules["go_auth_sso"]
	if !ok {
		t.Fatal("go_auth_sso routing override is missing")
	}
	if got, want := module.Mount.UIBase, "/admin/sso"; got != want {
		t.Fatalf("SSO mount = %q, want %q", got, want)
	}
}

func TestSupabaseProviderConfigDisablesGenericResourceRoleClaims(t *testing.T) {
	projectURL, err := parseApplicationURL("https://project-ref.supabase.co", false)
	if err != nil {
		t.Fatalf("parse project URL: %v", err)
	}
	appURL, err := parseApplicationURL("https://dashboard.example.test", false)
	if err != nil {
		t.Fatalf("parse app URL: %v", err)
	}
	cfg := newSupabaseProviderConfig(runtimeConfig{
		ProjectURL: projectURL,
		AppURL:     appURL,
		ClientID:   "dashboard-client",
	})
	if got, want := cfg.ClaimKeys.ResourceRoles, []string{"__supabase_disabled_resource_roles"}; !slices.Equal(got, want) {
		t.Fatalf("resource role claim keys = %#v, want %#v", got, want)
	}
}
