package oidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
)

const (
	DefaultResponseType  = "code"
	DefaultGrantType     = "authorization_code"
	DefaultScopeOpenID   = "openid"
	DefaultStateCapacity = 10_000
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
	Key          string
	Issuer       string
	DiscoveryURL string
	ClientID     string
	// Deprecated: use ClientSecretValue. This field remains source-compatible
	// for one release and is redacted from default output.
	ClientSecret             string
	ClientSecretValue        auth.Secret
	TokenEndpointAuthMethod  TokenEndpointAuthMethod
	RedirectURL              string
	Scopes                   []string
	Audience                 []string
	IDTokenAudience          []string
	AccessTokenAudience      []string
	RequireAccessTokenClaims bool
	AllowedAlgorithms        []string
	CacheTTL                 time.Duration
	JWKSRefreshCooldown      time.Duration
	// AllowInsecureHTTP permits provider and callback HTTP endpoints only when
	// their host is loopback. It is intended for local development and tests.
	AllowInsecureHTTP   bool
	UserInfo            bool
	Display             ProviderDisplay
	ClaimMapper         ClaimsMapper
	ClaimKeys           ClaimKeys
	AdditionalAuthParam map[string]string
	Limits              Limits
	RequestTimeout      time.Duration
}

type Limits struct {
	DiscoveryBodyBytes int64
	JWKSBodyBytes      int64
	UserInfoBodyBytes  int64
	TokenBodyBytes     int64
	EncodedTokenBytes  int
	CallbackCodeBytes  int
	CallbackStateBytes int
	RedirectBytes      int
	ProviderKeyBytes   int
	JWKSKeys           int
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
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	UserInfoEndpoint         string   `json:"userinfo_endpoint"`
	JWKSURI                  string   `json:"jwks_uri"`
	EndSessionEndpoint       string   `json:"end_session_endpoint,omitempty"`
	Algorithms               []string `json:"id_token_signing_alg_values_supported,omitempty"`
	Scopes                   []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

type TokenResponse struct {
	// Deprecated: use the secret-bearing Value fields.
	AccessToken       string
	IDToken           string
	RefreshToken      string
	AccessTokenValue  auth.Secret
	IDTokenValue      auth.Secret
	RefreshTokenValue auth.Secret
	TokenType         string `json:"token_type"`
	ExpiresIn         int64  `json:"expires_in,omitempty"`
	RefreshExpiresIn  int64  `json:"refresh_expires_in,omitempty"`
	Scope             string `json:"scope,omitempty"`
}

type TokenEndpointAuthMethod string

const (
	TokenEndpointAuthUnspecified       TokenEndpointAuthMethod = ""
	TokenEndpointAuthNone              TokenEndpointAuthMethod = "none"
	TokenEndpointAuthClientSecretBasic TokenEndpointAuthMethod = "client_secret_basic"
	TokenEndpointAuthClientSecretPost  TokenEndpointAuthMethod = "client_secret_post"
)

type AuthorizationRequest struct {
	ProviderKey string
	RedirectTo  string
	LoginHint   string
}

type AuthorizationResponse struct {
	ProviderKey string
	RedirectURL string
	// Deprecated: state is retained for source compatibility. HTTP adapters
	// must use RedirectURL and keep callback state server-side.
	State string
	// Deprecated: nonce is retained for source compatibility.
	Nonce string
	// Deprecated: PKCE verifier is retained for source compatibility.
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
	PrincipalTokenIssuer   PrincipalTokenIssuer
	PrincipalMapper        PrincipalMapper
	SessionHandoff         ProviderSessionHandoff
	SessionMode            BrowserSessionMode
	LocalClaimPolicy       LocalClaimPolicy
	DefaultRedirect        string
	AllowedRedirectOrigins []string
	Clock                  func() time.Time
	StateTTL               time.Duration
	StateCapacity          int
}

type BrowserSessionResult struct {
	LocalToken     string
	HostSession    auth.Secret
	Principal      auth.AuthenticatedPrincipal
	Identity       ExternalIdentity
	Claims         *auth.JWTClaims
	ProviderKey    string
	RedirectTarget string
	Audit          AuditMetadata
}

type BrowserSessionMode uint8

const (
	LocalTokenMode BrowserSessionMode = iota
	ProviderSessionMode
)

type LocalClaim string

const (
	LocalClaimProvider           LocalClaim = "provider"
	LocalClaimProviderSubject    LocalClaim = "provider_subject"
	LocalClaimProviderSessionID  LocalClaim = "provider_session_id"
	LocalClaimClientID           LocalClaim = "client_id"
	LocalClaimAssuranceLevel     LocalClaim = "assurance_level"
	LocalClaimAssuranceMethods   LocalClaim = "assurance_methods"
	LocalClaimAuthenticationTime LocalClaim = "authentication_time"
	LocalClaimTenantID           LocalClaim = "tenant_id"
	LocalClaimOrganizationID     LocalClaim = "organization_id"
	LocalClaimPermissionVersion  LocalClaim = "permission_version"
)

type LocalClaimPolicy struct {
	Allow []LocalClaim
}

func (p LocalClaimPolicy) Enabled() bool { return len(p.Allow) > 0 }

func (p LocalClaimPolicy) validate() error {
	known := map[LocalClaim]struct{}{
		LocalClaimProvider: {}, LocalClaimProviderSubject: {},
		LocalClaimProviderSessionID: {}, LocalClaimClientID: {},
		LocalClaimAssuranceLevel: {}, LocalClaimAssuranceMethods: {},
		LocalClaimAuthenticationTime: {}, LocalClaimTenantID: {},
		LocalClaimOrganizationID: {}, LocalClaimPermissionVersion: {},
	}
	seen := map[LocalClaim]struct{}{}
	for _, claim := range p.Allow {
		if _, ok := known[claim]; !ok {
			return cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "local_claim_policy", "claim": claim})
		}
		if _, ok := seen[claim]; ok {
			return cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "local_claim_policy", "cause": "duplicate claim"})
		}
		seen[claim] = struct{}{}
	}
	return nil
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

type ClaimSource string

const (
	ClaimSourceIDToken     ClaimSource = "id_token"
	ClaimSourceAccessToken ClaimSource = "access_token"
	ClaimSourceUserInfo    ClaimSource = "userinfo"
)

type ValidatedProviderIdentity struct {
	Provider          string
	Subject           string
	Email             string
	EmailVerified     bool
	Name              string
	GivenName         string
	FamilyName        string
	Nickname          string
	Picture           string
	ProviderSessionID string
	ClientID          string
	AssuranceLevel    string
	AssuranceMethods  []string
	AuthenticationAt  time.Time
	IssuedAt          time.Time
	ExpiresAt         time.Time
	TokenID           string
	TenantID          string
	OrganizationID    string
	PermissionVersion string
	ResourceRoles     map[string]string
	Metadata          map[string]string
	Provenance        map[string]ClaimSource
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
	CreatedAt    time.Time
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

type PrincipalTokenIssuer interface {
	GeneratePrincipal(identity auth.Identity, normalizedClaims map[string]any) (string, error)
}

type PrincipalTokenIssuerFunc func(auth.Identity, map[string]any) (string, error)

func (f PrincipalTokenIssuerFunc) GeneratePrincipal(identity auth.Identity, normalizedClaims map[string]any) (string, error) {
	if f == nil {
		return "", ErrInvalidConfig
	}
	return f(identity, normalizedClaims)
}

type PrincipalMapper interface {
	MapPrincipal(ctx context.Context, provider ProviderConfig, idToken auth.ValidatedTokenContext, accessToken *auth.ValidatedTokenContext, idClaims jwt.MapClaims, accessClaims jwt.MapClaims, userInfo map[string]any) (ValidatedProviderIdentity, error)
}

type PrincipalMapperFunc func(context.Context, ProviderConfig, auth.ValidatedTokenContext, *auth.ValidatedTokenContext, jwt.MapClaims, jwt.MapClaims, map[string]any) (ValidatedProviderIdentity, error)

func (f PrincipalMapperFunc) MapPrincipal(ctx context.Context, provider ProviderConfig, idToken auth.ValidatedTokenContext, accessToken *auth.ValidatedTokenContext, idClaims jwt.MapClaims, accessClaims jwt.MapClaims, userInfo map[string]any) (ValidatedProviderIdentity, error) {
	if f == nil {
		return ValidatedProviderIdentity{}, auth.ErrUnableToMapClaims
	}
	return f(ctx, provider, idToken, accessToken, idClaims, accessClaims, userInfo)
}

type ProviderSessionHandoff interface {
	CreateProviderSession(ctx context.Context, principal auth.AuthenticatedPrincipal, tokens auth.ProviderTokenSet) (ProviderSessionHandoffResult, error)
}

// ProviderSessionHandoffResult is the atomic output of server-side provider
// session creation. The local ID is bound to the normalized principal while the
// host session secret remains opaque.
type ProviderSessionHandoffResult struct {
	hostSession    auth.Secret
	localSessionID string
}

func NewProviderSessionHandoffResult(hostSession auth.Secret, localSessionID string) (ProviderSessionHandoffResult, error) {
	localSessionID = strings.TrimSpace(localSessionID)
	if hostSession.IsZero() || localSessionID == "" {
		return ProviderSessionHandoffResult{}, fmt.Errorf("oidc: provider session handoff requires an opaque host session and local session ID")
	}
	return ProviderSessionHandoffResult{
		hostSession:    hostSession,
		localSessionID: localSessionID,
	}, nil
}

func (r ProviderSessionHandoffResult) HostSession() auth.Secret { return r.hostSession }
func (r ProviderSessionHandoffResult) LocalSessionID() string   { return r.localSessionID }

type ProviderSessionHandoffFunc func(context.Context, auth.AuthenticatedPrincipal, auth.ProviderTokenSet) (ProviderSessionHandoffResult, error)

func (f ProviderSessionHandoffFunc) CreateProviderSession(ctx context.Context, principal auth.AuthenticatedPrincipal, tokens auth.ProviderTokenSet) (ProviderSessionHandoffResult, error) {
	if f == nil {
		return ProviderSessionHandoffResult{}, ErrInvalidConfig
	}
	return f(ctx, principal, tokens)
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
