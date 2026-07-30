package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
)

const (
	defaultAddress         = "127.0.0.1:8081"
	defaultAppURL          = "http://127.0.0.1:8081"
	defaultDatabaseDSN     = "file:supabase-dashboard.db?cache=shared&_pragma=foreign_keys(1)"
	defaultAccessAudience  = "authenticated"
	defaultTokenExpiration = 8
)

type runtimeConfig struct {
	Address               string
	AppURL                *url.URL
	DatabaseDSN           string
	ProjectURL            *url.URL
	ClientID              string
	ClientSecret          auth.Secret
	TokenEndpointAuth     oidc.TokenEndpointAuthMethod
	IDTokenAudience       []string
	AccessTokenAudience   []string
	AllowedAlgorithms     []string
	AllowInsecureLoopback bool
	SigningKey            auth.Secret
}

func loadRuntimeConfig() (runtimeConfig, error) {
	return loadRuntimeConfigFrom(os.Getenv)
}

func loadRuntimeConfigFrom(getenv func(string) string) (runtimeConfig, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}

	allowInsecure, err := parseBool(getenv("SUPABASE_ALLOW_INSECURE_LOOPBACK"))
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("SUPABASE_ALLOW_INSECURE_LOOPBACK: %w", err)
	}
	appURL, err := parseApplicationURL(valueOrDefault(getenv("APP_URL"), defaultAppURL), allowInsecure)
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("APP_URL: %w", err)
	}
	projectURL, err := parseApplicationURL(getenv("SUPABASE_PROJECT_URL"), allowInsecure)
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("SUPABASE_PROJECT_URL: %w", err)
	}
	if projectURL.Path != "" && projectURL.Path != "/" {
		return runtimeConfig{}, fmt.Errorf("SUPABASE_PROJECT_URL must be a project origin without a path")
	}

	clientID := strings.TrimSpace(getenv("SUPABASE_OAUTH_CLIENT_ID"))
	if clientID == "" {
		return runtimeConfig{}, fmt.Errorf("SUPABASE_OAUTH_CLIENT_ID is required")
	}
	clientSecret := auth.NewSecret(strings.TrimSpace(getenv("SUPABASE_OAUTH_CLIENT_SECRET")))
	method, err := parseTokenEndpointAuthMethod(getenv("SUPABASE_OAUTH_CLIENT_AUTH_METHOD"))
	if err != nil {
		return runtimeConfig{}, err
	}
	switch method {
	case oidc.TokenEndpointAuthNone:
		if !clientSecret.IsZero() {
			return runtimeConfig{}, fmt.Errorf("SUPABASE_OAUTH_CLIENT_SECRET must be empty when client auth method is none")
		}
	case oidc.TokenEndpointAuthClientSecretBasic, oidc.TokenEndpointAuthClientSecretPost:
		if clientSecret.IsZero() {
			return runtimeConfig{}, fmt.Errorf("SUPABASE_OAUTH_CLIENT_SECRET is required for confidential clients")
		}
	}

	signingKey := auth.NewSecret(strings.TrimSpace(getenv("GOAUTH_SIGNING_KEY")))
	if len(signingKey.Reveal()) < auth.MinimumHMACSigningKeyBytes {
		return runtimeConfig{}, fmt.Errorf("GOAUTH_SIGNING_KEY must be at least %d bytes", auth.MinimumHMACSigningKeyBytes)
	}

	algorithms := splitCSV(valueOrDefault(getenv("SUPABASE_ALLOWED_ALGORITHMS"), "ES256,RS256"))
	for _, algorithm := range algorithms {
		if algorithm != "ES256" && algorithm != "RS256" {
			return runtimeConfig{}, fmt.Errorf("SUPABASE_ALLOWED_ALGORITHMS supports only ES256 and RS256")
		}
	}
	idAudience := splitCSV(valueOrDefault(getenv("SUPABASE_ID_TOKEN_AUDIENCE"), clientID))
	accessAudience := splitCSV(valueOrDefault(getenv("SUPABASE_ACCESS_TOKEN_AUDIENCE"), defaultAccessAudience))
	if len(idAudience) == 0 || len(accessAudience) == 0 {
		return runtimeConfig{}, fmt.Errorf("Supabase ID-token and access-token audiences are required")
	}

	return runtimeConfig{
		Address:               valueOrDefault(getenv("SERVER_ADDR"), defaultAddress),
		AppURL:                appURL,
		DatabaseDSN:           valueOrDefault(getenv("DATABASE_DSN"), defaultDatabaseDSN),
		ProjectURL:            projectURL,
		ClientID:              clientID,
		ClientSecret:          clientSecret,
		TokenEndpointAuth:     method,
		IDTokenAudience:       idAudience,
		AccessTokenAudience:   accessAudience,
		AllowedAlgorithms:     algorithms,
		AllowInsecureLoopback: allowInsecure,
		SigningKey:            signingKey,
	}, nil
}

func (c runtimeConfig) callbackURL() string {
	out := *c.AppURL
	out.Path = path.Join(out.Path, "/admin/sso/callback/supabase")
	out.RawQuery = ""
	out.Fragment = ""
	return out.String()
}

func (c runtimeConfig) issuerURL() string {
	return strings.TrimRight(c.ProjectURL.String(), "/") + "/auth/v1"
}

func (c runtimeConfig) discoveryURL() string {
	return c.issuerURL() + "/.well-known/openid-configuration"
}

func (c runtimeConfig) secureCookies() bool {
	return strings.EqualFold(c.AppURL.Scheme, "https")
}

func (c runtimeConfig) authConfig() localAuthConfig {
	return localAuthConfig{signingKey: c.SigningKey}
}

func valueOrDefault(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func parseBool(value string) (bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, nil
	}
	return strconv.ParseBool(value)
}

func parseApplicationURL(raw string, allowInsecureLoopback bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("must be an absolute URL without credentials or fragment")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !allowInsecureLoopback || !isLoopback(parsed.Hostname()) {
			return nil, fmt.Errorf("HTTP is allowed only for an explicitly enabled loopback host")
		}
	default:
		return nil, fmt.Errorf("must use HTTPS or explicit loopback HTTP")
	}
	return parsed, nil
}

func isLoopback(host string) bool {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parseTokenEndpointAuthMethod(raw string) (oidc.TokenEndpointAuthMethod, error) {
	switch method := oidc.TokenEndpointAuthMethod(valueOrDefault(raw, string(oidc.TokenEndpointAuthClientSecretBasic))); method {
	case oidc.TokenEndpointAuthNone,
		oidc.TokenEndpointAuthClientSecretBasic,
		oidc.TokenEndpointAuthClientSecretPost:
		return method, nil
	default:
		return "", fmt.Errorf("SUPABASE_OAUTH_CLIENT_AUTH_METHOD must be none, client_secret_basic, or client_secret_post")
	}
}

func splitCSV(value string) []string {
	out := []string{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" && !slices.Contains(out, item) {
			out = append(out, item)
		}
	}
	return out
}

type localAuthConfig struct {
	signingKey auth.Secret
}

func (c localAuthConfig) GetSigningKey() string         { return c.signingKey.Reveal() }
func (localAuthConfig) GetSigningMethod() string        { return "HS256" }
func (localAuthConfig) GetContextKey() string           { return "go_admin_session" }
func (localAuthConfig) GetTokenExpiration() int         { return defaultTokenExpiration }
func (localAuthConfig) GetExtendedTokenDuration() int   { return 24 }
func (localAuthConfig) GetTokenLookup() string          { return "cookie:go_admin_session" }
func (localAuthConfig) GetAuthScheme() string           { return "Bearer" }
func (localAuthConfig) GetIssuer() string               { return "go-auth-supabase-dashboard" }
func (localAuthConfig) GetAudience() []string           { return []string{"go-admin"} }
func (localAuthConfig) GetRejectedRouteKey() string     { return "go_admin_return_to" }
func (localAuthConfig) GetRejectedRouteDefault() string { return "/admin/login" }
func (localAuthConfig) tokenDuration() time.Duration    { return defaultTokenExpiration * time.Hour }
func (localAuthConfig) extendedDuration() time.Duration { return 24 * time.Hour }
