package oidc

import (
	"context"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
)

const (
	DefaultResponseType = "code"
	DefaultGrantType    = "authorization_code"
	DefaultScopeOpenID  = "openid"
)

type Config struct {
	Providers              []ProviderConfig
	HTTPClient             *http.Client
	Clock                  func() time.Time
	AllowedRedirectOrigins []string
	DefaultRedirect        string
	StateTTL               time.Duration
	AllowSignup            bool
	EmailFallback          EmailFallbackPolicy
}

type ProviderConfig struct {
	Key                 string
	Issuer              string
	DiscoveryURL        string
	ClientID            string
	ClientSecret        string
	RedirectURL         string
	Scopes              []string
	Audience            []string
	IDTokenAudience     []string
	AllowedAlgorithms   []string
	CacheTTL            time.Duration
	UserInfo            bool
	Display             ProviderDisplay
	ClaimMapper         ClaimsMapper
	ClaimKeys           ClaimKeys
	AdditionalAuthParam map[string]string
}

type ClaimKeys struct {
	Roles          []string
	Groups         []string
	Permissions    []string
	ResourceRoles  []string
	TenantID       []string
	OrganizationID []string
}

type ProviderDisplay struct {
	Label          string
	Icon           string
	IconURL        string
	Disabled       bool
	DisabledReason string
}

type ProviderInfo struct {
	Key            string `json:"key"`
	Label          string `json:"label"`
	LoginURL       string `json:"login_url"`
	Icon           string `json:"icon,omitempty"`
	IconURL        string `json:"icon_url,omitempty"`
	DisabledReason string `json:"disabled_reason,omitempty"`
}

type Provider struct {
	Config    ProviderConfig
	Metadata  DiscoveryMetadata
	Validator *TokenValidator
}

type DiscoveryMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	EndSessionEndpoint    string   `json:"end_session_endpoint,omitempty"`
	Algorithms            []string `json:"id_token_signing_alg_values_supported,omitempty"`
	Scopes                []string `json:"scopes_supported,omitempty"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type AuthorizationRequest struct {
	ProviderKey string
	RedirectTo  string
	LoginHint   string
}

type AuthorizationResponse struct {
	ProviderKey  string
	RedirectURL  string
	State        string
	Nonce        string
	CodeVerifier string
	ExpiresAt    time.Time
}

type CallbackRequest struct {
	ProviderKey string
	Code        string
	State       string
	RedirectTo  string
}

type BrowserAuthenticatorConfig struct {
	Providers              []*Provider
	StateStore             StateStore
	TokenExchanger         TokenExchanger
	UserInfoFetcher        UserInfoFetcher
	IdentityLinker         IdentityLinker
	TokenIssuer            BrowserTokenIssuer
	DefaultRedirect        string
	AllowedRedirectOrigins []string
	Clock                  func() time.Time
	StateTTL               time.Duration
}

type BrowserSessionResult struct {
	LocalToken     string
	Identity       ExternalIdentity
	Claims         *auth.JWTClaims
	ProviderKey    string
	RedirectTarget string
	Audit          AuditMetadata
}

type AuditMetadata struct {
	EventType auth.ActivityEventType
	UserID    string
	Metadata  map[string]any
}

type ExternalIdentity struct {
	Provider       string
	Subject        string
	Email          string
	EmailVerified  bool
	Name           string
	GivenName      string
	FamilyName     string
	Nickname       string
	Picture        string
	TenantID       string
	OrganizationID string
	Roles          []string
	Permissions    []string
	ResourceRoles  map[string]string
	Metadata       map[string]any
}

type EmailFallbackPolicy struct {
	Enabled              bool
	RequireVerifiedEmail bool
}

type ClaimsMapper interface {
	MapClaims(ctx context.Context, provider ProviderConfig, claims jwt.MapClaims, userInfo map[string]any) (ExternalIdentity, *auth.JWTClaims, error)
}

type ClaimsMapperFunc func(ctx context.Context, provider ProviderConfig, claims jwt.MapClaims, userInfo map[string]any) (ExternalIdentity, *auth.JWTClaims, error)

func (f ClaimsMapperFunc) MapClaims(ctx context.Context, provider ProviderConfig, claims jwt.MapClaims, userInfo map[string]any) (ExternalIdentity, *auth.JWTClaims, error) {
	if f == nil {
		return ExternalIdentity{}, nil, auth.ErrUnableToMapClaims
	}
	return f(ctx, provider, claims, userInfo)
}

type StateStore interface {
	Save(ctx context.Context, state StateRecord) error
	Consume(ctx context.Context, state string) (StateRecord, error)
}

type StateRecord struct {
	State        string
	Nonce        string
	CodeVerifier string
	ProviderKey  string
	RedirectTo   string
	ExpiresAt    time.Time
}

type IdentityLinker interface {
	Resolve(ctx context.Context, identity ExternalIdentity) (auth.Identity, LinkingDecision, error)
}

type LinkingDecision struct {
	Action   string
	UserID   string
	Metadata map[string]any
}

type BrowserTokenIssuer interface {
	Generate(identity auth.Identity, resourceRoles map[string]string) (string, error)
}

type TokenExchanger interface {
	Exchange(ctx context.Context, provider ProviderConfig, metadata DiscoveryMetadata, code string, codeVerifier string) (TokenResponse, error)
}

type TokenExchangerFunc func(ctx context.Context, provider ProviderConfig, metadata DiscoveryMetadata, code string, codeVerifier string) (TokenResponse, error)

func (f TokenExchangerFunc) Exchange(ctx context.Context, provider ProviderConfig, metadata DiscoveryMetadata, code string, codeVerifier string) (TokenResponse, error) {
	if f == nil {
		return TokenResponse{}, ErrTokenExchangeFailed
	}
	return f(ctx, provider, metadata, code, codeVerifier)
}

type UserInfoFetcher interface {
	FetchUserInfo(ctx context.Context, provider ProviderConfig, metadata DiscoveryMetadata, accessToken string) (map[string]any, error)
}

type UserInfoFetcherFunc func(ctx context.Context, provider ProviderConfig, metadata DiscoveryMetadata, accessToken string) (map[string]any, error)

func (f UserInfoFetcherFunc) FetchUserInfo(ctx context.Context, provider ProviderConfig, metadata DiscoveryMetadata, accessToken string) (map[string]any, error) {
	if f == nil {
		return nil, ErrUserInfoFailed
	}
	return f(ctx, provider, metadata, accessToken)
}
