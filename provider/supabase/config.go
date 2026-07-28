package supabase

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
)

const (
	ProviderKey              = "supabase"
	DefaultAuthAPIVersion    = "2024-01-01"
	DefaultOAuthAPIVersion   = "2024-01-01"
	DefaultRequestTimeout    = 10 * time.Second
	DefaultResponseBodyBytes = int64(1 << 20)
)

var ErrInvalidConfig = errors.New("supabase: invalid configuration")

type Config struct {
	ProjectURL                string
	Issuer                    string
	DiscoveryURL              string
	ClientID                  string
	ClientSecret              auth.Secret
	TokenEndpointAuthMethod   oidc.TokenEndpointAuthMethod
	CallbackURL               string
	Scopes                    []string
	IDTokenAudience           []string
	AccessTokenAudience       []string
	AllowedAlgorithms         []string
	AuthorizationUIURL        string
	AllowedReturnURLs         []string
	AdminCredential           auth.Secret
	PublishableKey            auth.Secret
	ManagementCredential      auth.Secret
	Environment               string
	ProviderSessionDeployment auth.ProviderSessionDeployment
	AuthAPIVersion            string
	OAuthAPIVersion           string
	AllowInsecureLoopback     bool
	RequestTimeout            time.Duration
	ResponseBodyBytes         int64
}

//nolint:gocyclo,funlen // Provider security configuration is exhaustively validated in one public boundary.
func (c Config) Validate() error {
	project, err := validateEndpoint(c.ProjectURL, c.AllowInsecureLoopback, true)
	if err != nil {
		return configError("project_url", err.Error())
	}
	if project.Path != "" && project.Path != "/" {
		return configError("project_url", "must be a project origin without a path")
	}
	expectedIssuer := strings.TrimRight(project.String(), "/") + "/auth/v1"
	expectedDiscovery := expectedIssuer + "/.well-known/openid-configuration"
	if raw := strings.TrimRight(strings.TrimSpace(c.Issuer), "/"); raw != "" && raw != expectedIssuer {
		return configError("issuer", "must match the project auth issuer")
	}
	if raw := strings.TrimSpace(c.DiscoveryURL); raw != "" && raw != expectedDiscovery {
		return configError("discovery_url", "must match the project discovery endpoint")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return configError("client_id", "is required")
	}
	switch c.TokenEndpointAuthMethod {
	case oidc.TokenEndpointAuthNone:
		if !c.ClientSecret.IsZero() {
			return configError("client_secret", "must be absent for public clients")
		}
	case oidc.TokenEndpointAuthClientSecretBasic, oidc.TokenEndpointAuthClientSecretPost:
		if c.ClientSecret.IsZero() {
			return configError("client_secret", "is required for confidential clients")
		}
	default:
		return configError("token_endpoint_auth_method", "is unsupported")
	}
	if _, err := validateEndpoint(c.CallbackURL, c.AllowInsecureLoopback, true); err != nil {
		return configError("callback_url", err.Error())
	}
	if _, err := validateEndpoint(c.AuthorizationUIURL, c.AllowInsecureLoopback, false); err != nil {
		return configError("authorization_ui_url", err.Error())
	}
	if err := validateScopes(c.Scopes); err != nil {
		return err
	}
	if err := validateUniqueValues("id_token_audience", c.IDTokenAudience); err != nil {
		return err
	}
	if err := validateUniqueValues("access_token_audience", c.AccessTokenAudience); err != nil {
		return err
	}
	if len(compact(c.IDTokenAudience)) == 0 || len(compact(c.AccessTokenAudience)) == 0 {
		return configError("audience", "ID-token and access-token audiences are required")
	}
	if err := validateAlgorithms(c.AllowedAlgorithms); err != nil {
		return err
	}
	if strings.TrimSpace(c.Environment) == "" {
		return configError("environment", "is required")
	}
	if c.ProviderSessionDeployment == "" {
		return configError("provider_session_deployment", "is required")
	}
	if err := c.ProviderSessionDeployment.Validate(); err != nil {
		return configError("provider_session_deployment", "is invalid")
	}
	if c.AdminCredential.IsZero() || c.PublishableKey.IsZero() {
		return configError("credentials", "admin and publishable credentials are required")
	}
	if sameSecret(c.AdminCredential, c.PublishableKey) ||
		(!c.ManagementCredential.IsZero() &&
			(sameSecret(c.ManagementCredential, c.AdminCredential) ||
				sameSecret(c.ManagementCredential, c.PublishableKey))) {
		return configError("credentials", "credential roles must use distinct values")
	}
	if len(c.AllowedReturnURLs) == 0 {
		return configError("allowed_return_urls", "at least one exact return URL is required")
	}
	seenReturns := map[string]struct{}{}
	for _, raw := range c.AllowedReturnURLs {
		parsed, err := validateEndpoint(raw, c.AllowInsecureLoopback, false)
		if err != nil {
			return configError("allowed_return_urls", err.Error())
		}
		normalized := parsed.String()
		if _, exists := seenReturns[normalized]; exists {
			return configError("allowed_return_urls", "contains a duplicate")
		}
		seenReturns[normalized] = struct{}{}
	}
	if strings.TrimSpace(c.AuthAPIVersion) == "" || strings.TrimSpace(c.OAuthAPIVersion) == "" {
		return configError("api_version", "auth and OAuth API versions are required")
	}
	if c.RequestTimeout <= 0 || c.RequestTimeout > time.Minute {
		return configError("request_timeout", "must be between zero and one minute")
	}
	if c.ResponseBodyBytes <= 0 || c.ResponseBodyBytes > 8<<20 {
		return configError("response_body_bytes", "must be between zero and eight MiB")
	}
	return nil
}

func (c Config) WithDefaults() Config {
	c.ProjectURL = strings.TrimRight(strings.TrimSpace(c.ProjectURL), "/")
	if c.Issuer == "" && c.ProjectURL != "" {
		c.Issuer = c.ProjectURL + "/auth/v1"
	}
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	if c.DiscoveryURL == "" && c.Issuer != "" {
		c.DiscoveryURL = c.Issuer + "/.well-known/openid-configuration"
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	if len(c.AllowedAlgorithms) == 0 {
		c.AllowedAlgorithms = []string{"RS256", "ES256"}
	}
	if c.AuthAPIVersion == "" {
		c.AuthAPIVersion = DefaultAuthAPIVersion
	}
	if c.OAuthAPIVersion == "" {
		c.OAuthAPIVersion = DefaultOAuthAPIVersion
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = DefaultRequestTimeout
	}
	if c.ResponseBodyBytes == 0 {
		c.ResponseBodyBytes = DefaultResponseBodyBytes
	}
	return c
}

func (c Config) OIDCConfig() (oidc.ProviderConfig, error) {
	c = c.WithDefaults()
	if err := c.Validate(); err != nil {
		return oidc.ProviderConfig{}, err
	}
	return oidc.ProviderConfig{
		Key:                      ProviderKey,
		Issuer:                   c.Issuer,
		DiscoveryURL:             c.DiscoveryURL,
		ClientID:                 strings.TrimSpace(c.ClientID),
		ClientSecretValue:        c.ClientSecret,
		TokenEndpointAuthMethod:  c.TokenEndpointAuthMethod,
		RedirectURL:              strings.TrimSpace(c.CallbackURL),
		Scopes:                   compact(c.Scopes),
		IDTokenAudience:          compact(c.IDTokenAudience),
		AccessTokenAudience:      compact(c.AccessTokenAudience),
		RequireAccessTokenClaims: true,
		AllowedAlgorithms:        compact(c.AllowedAlgorithms),
		AllowInsecureHTTP:        c.AllowInsecureLoopback,
		RequestTimeout:           c.RequestTimeout,
		Display:                  oidc.ProviderDisplay{Label: "Supabase", Icon: "supabase"},
		ClaimKeys: oidc.ClaimKeys{
			ResourceRoles: []string{"__supabase_disabled_resource_roles"},
		},
	}, nil
}

func (c Config) PrincipalMapper(allowedHookClaims ...string) (oidc.PrincipalMapper, error) {
	c = c.WithDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	mapper := ClaimsMapper{
		AllowedHookClaims: compact(allowedHookClaims),
		AllowedUserRoles:  []string{"authenticated"},
	}
	if slices.ContainsFunc(mapper.AllowedHookClaims, forbiddenHookClaim) {
		return nil, configError("allowed_hook_claims", "contains an authorization-sensitive claim")
	}
	return mapper, nil
}

// SubjectIDStrategy returns the opt-in linker strategy that preserves a
// validated Supabase UUID subject as the local user ID.
func SubjectIDStrategy() oidc.IdentityIDStrategy {
	return oidc.ProviderSubjectUUIDIDStrategy{Provider: ProviderKey}
}

func (c Config) ReturnURLAllowed(raw string) bool {
	c = c.WithDefaults()
	parsed, err := validateEndpoint(raw, c.AllowInsecureLoopback, false)
	if err != nil {
		return false
	}
	for _, allowed := range c.AllowedReturnURLs {
		candidate, candidateErr := validateEndpoint(allowed, c.AllowInsecureLoopback, false)
		if candidateErr == nil && candidate.String() == parsed.String() {
			return true
		}
	}
	return false
}

func (c Config) String() string {
	return fmt.Sprintf("supabase.Config{ProjectURL:%q Issuer:%q ClientID:%q ClientSecret:[REDACTED] AdminCredential:[REDACTED] PublishableKey:[REDACTED] ManagementCredential:[REDACTED] Environment:%q}",
		c.ProjectURL, c.Issuer, c.ClientID, c.Environment)
}
func (c Config) GoString() string               { return c.String() }
func (c Config) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(c.String())) }
func (c Config) LogValue() slog.Value           { return slog.StringValue(c.String()) }
func (c Config) MarshalJSON() ([]byte, error)   { return nil, auth.ErrSecretSerialization }
func (c Config) MarshalText() ([]byte, error)   { return nil, auth.ErrSecretSerialization }

var _ json.Marshaler = Config{}

func configError(field, cause string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidConfig, field, cause)
}

func validateEndpoint(raw string, allowInsecureLoopback, noQuery bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("must be an absolute URL without credentials or fragment")
	}
	if noQuery && parsed.RawQuery != "" {
		return nil, errors.New("must not contain a query")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !allowInsecureLoopback || !isLoopback(parsed.Hostname()) {
			return nil, errors.New("must use HTTPS or explicit loopback HTTP")
		}
	default:
		return nil, errors.New("must use HTTPS or explicit loopback HTTP")
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

func validateScopes(scopes []string) error {
	normalized := compact(scopes)
	if len(normalized) != len(scopes) || !slices.Contains(normalized, "openid") {
		return configError("scopes", "must be unique and include openid")
	}
	allowed := []string{"openid", "profile", "email", "offline_access"}
	for _, scope := range normalized {
		if !slices.Contains(allowed, scope) {
			return configError("scopes", "contains an unsupported scope")
		}
	}
	return nil
}

func validateAlgorithms(algorithms []string) error {
	normalized := compact(algorithms)
	if len(normalized) != len(algorithms) || len(normalized) == 0 {
		return configError("allowed_algorithms", "must be non-empty and unique")
	}
	for _, algorithm := range normalized {
		if algorithm != "RS256" && algorithm != "ES256" {
			return configError("allowed_algorithms", "supports only RS256 and ES256")
		}
	}
	return nil
}

func validateUniqueValues(field string, values []string) error {
	normalized := compact(values)
	if len(normalized) != len(values) {
		return configError(field, "must be non-empty and unique")
	}
	return nil
}

func sameSecret(a, b auth.Secret) bool {
	return !a.IsZero() && !b.IsZero() && a.Reveal() == b.Reveal()
}

func compact(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" && !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	return out
}
