package auth

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"
)

const (
	DefaultPrincipalMetadataEntries = 32
	DefaultPrincipalMetadataBytes   = 16 * 1024
	redactedSecret                  = "[REDACTED]"
)

var (
	ErrSecretSerialization = errors.New("auth: secret serialization is disabled")
	ErrInvalidTokenSet     = errors.New("auth: invalid provider token set")
	ErrInvalidPrincipal    = errors.New("auth: invalid authenticated principal")
)

// Secret is an opaque secret value. It must be explicitly revealed by trusted
// server-side code and fails closed when passed to common serializers.
type Secret struct {
	value string
}

var (
	_ fmt.Stringer             = Secret{}
	_ fmt.GoStringer           = Secret{}
	_ fmt.Formatter            = Secret{}
	_ slog.LogValuer           = Secret{}
	_ json.Marshaler           = Secret{}
	_ encoding.TextMarshaler   = Secret{}
	_ encoding.TextUnmarshaler = (*Secret)(nil)
)

func NewSecret(value string) Secret { return Secret{value: value} }

func (s Secret) Reveal() string { return s.value }

func (s Secret) IsZero() bool { return s.value == "" }

func (s Secret) String() string { return redactedSecret }

func (s Secret) GoString() string { return "auth.Secret(" + redactedSecret + ")" }

func (s Secret) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedSecret))
}

func (s Secret) LogValue() slog.Value { return slog.StringValue(redactedSecret) }

func (s Secret) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

func (s Secret) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

func (s *Secret) UnmarshalText([]byte) error { return ErrSecretSerialization }

// ValidatedTokenContext contains only independently validated, typed claims.
// It deliberately excludes arbitrary raw provider claim maps.
type ValidatedTokenContext struct {
	Issuer            string
	Subject           string
	Audiences         []string
	SessionID         string
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
}

func (c ValidatedTokenContext) Clone() ValidatedTokenContext {
	c.Audiences = slices.Clone(c.Audiences)
	c.AssuranceMethods = slices.Clone(c.AssuranceMethods)
	return c
}

// ProviderTokenSetInput is the construction boundary for a provider token set.
type ProviderTokenSetInput struct {
	AccessToken      Secret
	RefreshToken     Secret
	IDToken          Secret
	TokenType        string
	Scopes           []string
	AcquiredAt       time.Time
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	IDExpiresAt      time.Time
	IDContext        *ValidatedTokenContext
	AccessContext    *ValidatedTokenContext
	Metadata         map[string]string
}

// ProviderTokenSet keeps provider credentials opaque and non-serializable.
type ProviderTokenSet struct {
	accessToken      Secret
	refreshToken     Secret
	idToken          Secret
	tokenType        string
	scopes           []string
	acquiredAt       time.Time
	accessExpiresAt  time.Time
	refreshExpiresAt time.Time
	idExpiresAt      time.Time
	idContext        *ValidatedTokenContext
	accessContext    *ValidatedTokenContext
	metadata         map[string]string
}

var (
	_ fmt.Stringer           = ProviderTokenSet{}
	_ fmt.GoStringer         = ProviderTokenSet{}
	_ fmt.Formatter          = ProviderTokenSet{}
	_ slog.LogValuer         = ProviderTokenSet{}
	_ json.Marshaler         = ProviderTokenSet{}
	_ encoding.TextMarshaler = ProviderTokenSet{}
)

func NewProviderTokenSet(input ProviderTokenSetInput) (ProviderTokenSet, error) {
	if input.AccessToken.IsZero() && input.RefreshToken.IsZero() && input.IDToken.IsZero() {
		return ProviderTokenSet{}, fmt.Errorf("%w: at least one token is required", ErrInvalidTokenSet)
	}
	metadata, err := boundedStringMetadata(input.Metadata, DefaultPrincipalMetadataEntries, DefaultPrincipalMetadataBytes)
	if err != nil {
		return ProviderTokenSet{}, fmt.Errorf("%w: %v", ErrInvalidTokenSet, err)
	}
	out := ProviderTokenSet{
		accessToken:      input.AccessToken,
		refreshToken:     input.RefreshToken,
		idToken:          input.IDToken,
		tokenType:        strings.TrimSpace(input.TokenType),
		scopes:           compactStrings(input.Scopes),
		acquiredAt:       input.AcquiredAt,
		accessExpiresAt:  input.AccessExpiresAt,
		refreshExpiresAt: input.RefreshExpiresAt,
		idExpiresAt:      input.IDExpiresAt,
		metadata:         metadata,
	}
	if input.IDContext != nil {
		ctx := input.IDContext.Clone()
		out.idContext = &ctx
	}
	if input.AccessContext != nil {
		ctx := input.AccessContext.Clone()
		out.accessContext = &ctx
	}
	return out, nil
}

func (s ProviderTokenSet) AccessToken() Secret         { return s.accessToken }
func (s ProviderTokenSet) RefreshToken() Secret        { return s.refreshToken }
func (s ProviderTokenSet) IDToken() Secret             { return s.idToken }
func (s ProviderTokenSet) TokenType() string           { return s.tokenType }
func (s ProviderTokenSet) Scopes() []string            { return slices.Clone(s.scopes) }
func (s ProviderTokenSet) AcquiredAt() time.Time       { return s.acquiredAt }
func (s ProviderTokenSet) AccessExpiresAt() time.Time  { return s.accessExpiresAt }
func (s ProviderTokenSet) RefreshExpiresAt() time.Time { return s.refreshExpiresAt }
func (s ProviderTokenSet) IDExpiresAt() time.Time      { return s.idExpiresAt }
func (s ProviderTokenSet) Metadata() map[string]string { return cloneProviderStringMap(s.metadata) }

func (s ProviderTokenSet) IDContext() (ValidatedTokenContext, bool) {
	if s.idContext == nil {
		return ValidatedTokenContext{}, false
	}
	return s.idContext.Clone(), true
}

func (s ProviderTokenSet) AccessContext() (ValidatedTokenContext, bool) {
	if s.accessContext == nil {
		return ValidatedTokenContext{}, false
	}
	return s.accessContext.Clone(), true
}

func (s ProviderTokenSet) String() string                 { return "auth.ProviderTokenSet(" + redactedSecret + ")" }
func (s ProviderTokenSet) GoString() string               { return s.String() }
func (s ProviderTokenSet) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(s.String())) }
func (s ProviderTokenSet) LogValue() slog.Value           { return slog.StringValue(s.String()) }
func (s ProviderTokenSet) MarshalJSON() ([]byte, error)   { return nil, ErrSecretSerialization }
func (s ProviderTokenSet) MarshalText() ([]byte, error)   { return nil, ErrSecretSerialization }

// AuthenticatedPrincipalInput is accepted only after provider identity linking.
type AuthenticatedPrincipalInput struct {
	ApplicationSubject string
	Provider           string
	ProviderSubject    string
	ProviderSessionID  string
	LocalSessionID     string
	ClientID           string
	AssuranceLevel     string
	AssuranceMethods   []string
	AuthenticationAt   time.Time
	IssuedAt           time.Time
	ExpiresAt          time.Time
	TokenID            string
	TenantID           string
	OrganizationID     string
	PermissionVersion  string
	Metadata           map[string]string
}

type AuthenticatedPrincipal struct {
	applicationSubject string
	provider           string
	providerSubject    string
	providerSessionID  string
	localSessionID     string
	clientID           string
	assuranceLevel     string
	assuranceMethods   []string
	authenticationAt   time.Time
	issuedAt           time.Time
	expiresAt          time.Time
	tokenID            string
	tenantID           string
	organizationID     string
	permissionVersion  string
	metadata           map[string]string
}

func NewAuthenticatedPrincipal(input AuthenticatedPrincipalInput) (AuthenticatedPrincipal, error) {
	if strings.TrimSpace(input.ApplicationSubject) == "" ||
		strings.TrimSpace(input.Provider) == "" ||
		strings.TrimSpace(input.ProviderSubject) == "" {
		return AuthenticatedPrincipal{}, fmt.Errorf("%w: application subject, provider, and provider subject are required", ErrInvalidPrincipal)
	}
	metadata, err := boundedStringMetadata(input.Metadata, DefaultPrincipalMetadataEntries, DefaultPrincipalMetadataBytes)
	if err != nil {
		return AuthenticatedPrincipal{}, fmt.Errorf("%w: %v", ErrInvalidPrincipal, err)
	}
	return AuthenticatedPrincipal{
		applicationSubject: strings.TrimSpace(input.ApplicationSubject),
		provider:           strings.TrimSpace(input.Provider),
		providerSubject:    strings.TrimSpace(input.ProviderSubject),
		providerSessionID:  strings.TrimSpace(input.ProviderSessionID),
		localSessionID:     strings.TrimSpace(input.LocalSessionID),
		clientID:           strings.TrimSpace(input.ClientID),
		assuranceLevel:     strings.TrimSpace(input.AssuranceLevel),
		assuranceMethods:   compactStrings(input.AssuranceMethods),
		authenticationAt:   input.AuthenticationAt,
		issuedAt:           input.IssuedAt,
		expiresAt:          input.ExpiresAt,
		tokenID:            strings.TrimSpace(input.TokenID),
		tenantID:           strings.TrimSpace(input.TenantID),
		organizationID:     strings.TrimSpace(input.OrganizationID),
		permissionVersion:  strings.TrimSpace(input.PermissionVersion),
		metadata:           metadata,
	}, nil
}

func (p AuthenticatedPrincipal) Clone() AuthenticatedPrincipal {
	p.assuranceMethods = slices.Clone(p.assuranceMethods)
	p.metadata = cloneProviderStringMap(p.metadata)
	return p
}

// BindLocalSessionID returns a copy associated with the host session created
// after provider identity linking. Rebinding to a different session fails.
func (p AuthenticatedPrincipal) BindLocalSessionID(localSessionID string) (AuthenticatedPrincipal, error) {
	localSessionID = strings.TrimSpace(localSessionID)
	if localSessionID == "" {
		return AuthenticatedPrincipal{}, fmt.Errorf("%w: local session ID is required", ErrInvalidPrincipal)
	}
	if p.localSessionID != "" && p.localSessionID != localSessionID {
		return AuthenticatedPrincipal{}, fmt.Errorf("%w: local session ID is already bound", ErrInvalidPrincipal)
	}
	p.localSessionID = localSessionID
	return p.Clone(), nil
}

func (p AuthenticatedPrincipal) ApplicationSubject() string { return p.applicationSubject }
func (p AuthenticatedPrincipal) Provider() string           { return p.provider }
func (p AuthenticatedPrincipal) ProviderSubject() string    { return p.providerSubject }
func (p AuthenticatedPrincipal) ProviderSessionID() string  { return p.providerSessionID }
func (p AuthenticatedPrincipal) LocalSessionID() string     { return p.localSessionID }
func (p AuthenticatedPrincipal) ClientID() string           { return p.clientID }
func (p AuthenticatedPrincipal) AssuranceLevel() string     { return p.assuranceLevel }
func (p AuthenticatedPrincipal) AssuranceMethods() []string {
	return slices.Clone(p.assuranceMethods)
}
func (p AuthenticatedPrincipal) AuthenticationAt() time.Time { return p.authenticationAt }
func (p AuthenticatedPrincipal) IssuedAt() time.Time         { return p.issuedAt }
func (p AuthenticatedPrincipal) ExpiresAt() time.Time        { return p.expiresAt }
func (p AuthenticatedPrincipal) TokenID() string             { return p.tokenID }
func (p AuthenticatedPrincipal) TenantID() string            { return p.tenantID }
func (p AuthenticatedPrincipal) OrganizationID() string      { return p.organizationID }
func (p AuthenticatedPrincipal) PermissionVersion() string   { return p.permissionVersion }
func (p AuthenticatedPrincipal) Metadata() map[string]string {
	return cloneProviderStringMap(p.metadata)
}

func boundedStringMetadata(in map[string]string, maxEntries, maxBytes int) (map[string]string, error) {
	if len(in) > maxEntries {
		return nil, fmt.Errorf("metadata has %d entries; limit is %d", len(in), maxEntries)
	}
	out := make(map[string]string, len(in))
	total := 0
	for key, value := range in {
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, errors.New("metadata key is empty")
		}
		total += len(key) + len(value)
		if total > maxBytes {
			return nil, fmt.Errorf("metadata is %d bytes; limit is %d", total, maxBytes)
		}
		out[key] = value
	}
	return out, nil
}

func compactStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, value := range in {
		if value = strings.TrimSpace(value); value != "" && !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	return out
}

func cloneProviderStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	maps.Copy(out, in)
	return out
}
