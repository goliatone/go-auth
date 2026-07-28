package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
)

const (
	DefaultProviderSessionCookieName = "__Host-go_auth_ps"
	DefaultProviderSessionTouch      = 5 * time.Minute
	DefaultProviderRefreshLease      = 30 * time.Second
	DefaultProviderSessionRetention  = 30 * 24 * time.Hour
	DefaultProviderTokenRetention    = 24 * time.Hour
	MaxProviderTokenPayloadBytes     = 64 * 1024
	MaxProviderTokenKeyIDBytes       = 128
)

var (
	ErrProviderSessionInvalid         = errors.New("auth: invalid provider session")
	ErrProviderSessionNotFound        = errors.New("auth: provider session not found")
	ErrProviderSessionExpired         = errors.New("auth: provider session expired")
	ErrProviderSessionRevoked         = errors.New("auth: provider session revoked")
	ErrProviderSessionUncertain       = errors.New("auth: provider session refresh outcome is uncertain")
	ErrProviderSessionConflict        = errors.New("auth: provider session revision conflict")
	ErrProviderSessionBinding         = errors.New("auth: provider session binding mismatch")
	ErrProviderSessionUnavailable     = errors.New("auth: provider session unavailable")
	ErrProviderSessionCredential      = errors.New("auth: conflicting authentication credentials")
	ErrProviderRefreshInProgress      = errors.New("auth: provider session refresh in progress")
	ErrProviderRefreshRejected        = errors.New("auth: provider refresh rejected")
	ErrProviderRefreshAmbiguous       = errors.New("auth: provider refresh outcome ambiguous")
	ErrProviderTokenCipher            = errors.New("auth: provider token cipher failure")
	ErrProviderTokenKeyNotFound       = errors.New("auth: provider token key not found")
	ErrProviderTokenKeyRetired        = errors.New("auth: provider token key is retired")
	ErrProviderTokenEnvelope          = errors.New("auth: invalid provider token envelope")
	ErrProviderTokenTarget            = errors.New("auth: invalid provider token target")
	ErrProviderTokenPolicy            = errors.New("auth: provider token access denied")
	ErrProviderTokenPolicyUnavailable = errors.New("auth: provider token access policy unavailable")
)

type ProviderSessionStatus string

const (
	ProviderSessionAvailable  ProviderSessionStatus = "available"
	ProviderSessionRefreshing ProviderSessionStatus = "refreshing"
	ProviderSessionUncertain  ProviderSessionStatus = "uncertain"
	ProviderSessionRevoked    ProviderSessionStatus = "revoked"
	ProviderSessionExpired    ProviderSessionStatus = "expired"
)

func (s ProviderSessionStatus) Usable() bool {
	return s == ProviderSessionAvailable
}

// ProviderSessionBinding prevents an opaque browser handle from being copied
// between applications, environments, issuers, or OAuth clients.
type ProviderSessionBinding struct {
	Host          string
	ApplicationID string
	Environment   string
	TenantID      string
	Provider      string
	Issuer        string
	ClientID      string
}

func (b ProviderSessionBinding) Validate() error {
	switch {
	case strings.TrimSpace(b.Host) == "":
		return fmt.Errorf("%w: host is required", ErrProviderSessionBinding)
	case strings.TrimSpace(b.ApplicationID) == "":
		return fmt.Errorf("%w: application is required", ErrProviderSessionBinding)
	case strings.TrimSpace(b.Environment) == "":
		return fmt.Errorf("%w: environment is required", ErrProviderSessionBinding)
	case strings.TrimSpace(b.Provider) == "":
		return fmt.Errorf("%w: provider is required", ErrProviderSessionBinding)
	case strings.TrimSpace(b.Issuer) == "":
		return fmt.Errorf("%w: issuer is required", ErrProviderSessionBinding)
	case strings.TrimSpace(b.ClientID) == "":
		return fmt.Errorf("%w: client is required", ErrProviderSessionBinding)
	default:
		return nil
	}
}

func (b ProviderSessionBinding) normalized() ProviderSessionBinding {
	b.Host = strings.ToLower(strings.TrimSpace(b.Host))
	b.ApplicationID = strings.TrimSpace(b.ApplicationID)
	b.Environment = strings.TrimSpace(b.Environment)
	b.TenantID = strings.TrimSpace(b.TenantID)
	b.Provider = strings.TrimSpace(b.Provider)
	b.Issuer = strings.TrimRight(strings.TrimSpace(b.Issuer), "/")
	b.ClientID = strings.TrimSpace(b.ClientID)
	return b
}

func (b ProviderSessionBinding) Equal(other ProviderSessionBinding) bool {
	return b.normalized() == other.normalized()
}

// PrincipalSnapshot is the non-secret persistence representation of a
// normalized principal.
type PrincipalSnapshot struct {
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

func NewPrincipalSnapshot(principal AuthenticatedPrincipal) PrincipalSnapshot {
	return PrincipalSnapshot{
		ApplicationSubject: principal.ApplicationSubject(),
		Provider:           principal.Provider(),
		ProviderSubject:    principal.ProviderSubject(),
		ProviderSessionID:  principal.ProviderSessionID(),
		LocalSessionID:     principal.LocalSessionID(),
		ClientID:           principal.ClientID(),
		AssuranceLevel:     principal.AssuranceLevel(),
		AssuranceMethods:   principal.AssuranceMethods(),
		AuthenticationAt:   principal.AuthenticationAt(),
		IssuedAt:           principal.IssuedAt(),
		ExpiresAt:          principal.ExpiresAt(),
		TokenID:            principal.TokenID(),
		TenantID:           principal.TenantID(),
		OrganizationID:     principal.OrganizationID(),
		PermissionVersion:  principal.PermissionVersion(),
		Metadata:           principal.Metadata(),
	}
}

func (p PrincipalSnapshot) Principal() (AuthenticatedPrincipal, error) {
	return NewAuthenticatedPrincipal(AuthenticatedPrincipalInput{
		ApplicationSubject: p.ApplicationSubject,
		Provider:           p.Provider,
		ProviderSubject:    p.ProviderSubject,
		ProviderSessionID:  p.ProviderSessionID,
		LocalSessionID:     p.LocalSessionID,
		ClientID:           p.ClientID,
		AssuranceLevel:     p.AssuranceLevel,
		AssuranceMethods:   slices.Clone(p.AssuranceMethods),
		AuthenticationAt:   p.AuthenticationAt,
		IssuedAt:           p.IssuedAt,
		ExpiresAt:          p.ExpiresAt,
		TokenID:            p.TokenID,
		TenantID:           p.TenantID,
		OrganizationID:     p.OrganizationID,
		PermissionVersion:  p.PermissionVersion,
		Metadata:           cloneProviderStringMap(p.Metadata),
	})
}

// ProviderSession never includes the browser handle, lookup hash, or provider
// tokens. ID is internal; LocalSessionID is safe for audit and CSRF keys.
type ProviderSession struct {
	ID                  string
	LocalSessionID      string
	Principal           PrincipalSnapshot
	Binding             ProviderSessionBinding
	Status              ProviderSessionStatus
	TokenRevision       int64
	CreatedAt           time.Time
	LastSeenAt          time.Time
	IdleExpiresAt       time.Time
	MaxExpiresAt        time.Time
	RefreshAttemptID    string
	RefreshBaseRevision int64
	RefreshLeaseUntil   time.Time
	RevokedAt           time.Time
	// Deprecated: contains only the typed reason code after remediation.
	RevocationReason            string
	RevocationReasonCode        ProviderSessionReasonCode
	RevocationReasonFingerprint ProviderAuditFingerprint
	RemoteRevocation            ProviderRemoteRevocationOutcome
	RemoteAttemptCount          int
	RemoteNextAttemptAt         time.Time
	RemoteLeaseOwner            string
	RemoteLeaseUntil            time.Time
	RemoteRevision              int64
	RemoteSafeErrorCode         string
	RemoteWorkExpiresAt         time.Time
	RemoteTerminalAt            time.Time
}

func (s ProviderSession) String() string {
	return fmt.Sprintf("auth.ProviderSession{id:%q, local_session_id:%q, status:%q, revision:%d}",
		s.ID, s.LocalSessionID, s.Status, s.TokenRevision)
}

func (s ProviderSession) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("local_session_id", s.LocalSessionID),
		slog.String("status", string(s.Status)),
		slog.Int64("revision", s.TokenRevision),
	)
}

type TokenEnvelope struct {
	Version    uint8
	Algorithm  string
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

func (e TokenEnvelope) String() string {
	return fmt.Sprintf("auth.TokenEnvelope{version:%d, algorithm:%q, key_id:%q, ciphertext:%s}",
		e.Version, e.Algorithm, e.KeyID, redactedSecret)
}

func (e TokenEnvelope) GoString() string { return e.String() }

func (e TokenEnvelope) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(e.String()))
}

func (e TokenEnvelope) MarshalJSON() ([]byte, error) {
	return nil, ErrSecretSerialization
}

func (e TokenEnvelope) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("version", int(e.Version)),
		slog.String("algorithm", e.Algorithm),
		slog.String("key_id", e.KeyID),
		slog.String("ciphertext", redactedSecret),
	)
}

var _ json.Marshaler = TokenEnvelope{}

type TokenEncryptionKey struct {
	id       string
	material []byte
	retired  bool
}

func NewTokenEncryptionKey(id string, material []byte, retired bool) (TokenEncryptionKey, error) {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > MaxProviderTokenKeyIDBytes || len(material) != 32 {
		return TokenEncryptionKey{}, ErrProviderTokenKeyNotFound
	}
	return TokenEncryptionKey{id: id, material: append([]byte(nil), material...), retired: retired}, nil
}

func (k TokenEncryptionKey) ID() string       { return k.id }
func (k TokenEncryptionKey) Retired() bool    { return k.retired }
func (k TokenEncryptionKey) Material() []byte { return append([]byte(nil), k.material...) }
func (k TokenEncryptionKey) String() string   { return "auth.TokenEncryptionKey(" + redactedSecret + ")" }
func (k TokenEncryptionKey) GoString() string { return k.String() }
func (k TokenEncryptionKey) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(k.String()))
}
func (k TokenEncryptionKey) LogValue() slog.Value { return slog.StringValue(k.String()) }
func (k TokenEncryptionKey) MarshalJSON() ([]byte, error) {
	return nil, ErrSecretSerialization
}

type TokenKeyProvider interface {
	ActiveKey(ctx context.Context) (TokenEncryptionKey, error)
	Key(ctx context.Context, keyID string) (TokenEncryptionKey, error)
}

type TokenCipher interface {
	Seal(ctx context.Context, plaintext []byte, associatedData []byte) (TokenEnvelope, error)
	Open(ctx context.Context, envelope TokenEnvelope, associatedData []byte) ([]byte, error)
}

type ProviderSessionCreate struct {
	Session    ProviderSession
	LookupHash []byte
	Tokens     TokenEnvelope
}

type ProviderSessionResolution struct {
	Session ProviderSession
	Tokens  TokenEnvelope
}

type ProviderRefreshClaim struct {
	Session   ProviderSession
	Tokens    TokenEnvelope
	AttemptID string
	Acquired  bool
}

type ProviderRefreshCommit struct {
	SessionID        string
	AttemptID        string
	BaseRevision     int64
	Tokens           TokenEnvelope
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

type ProviderSessionCleanupPolicy struct {
	Now              time.Time
	SessionRetention time.Duration
	TokenRetention   time.Duration
	BatchSize        int
}

type ProviderSessionCleanupResult struct {
	StateRecords   int64
	SessionRecords int64
	TokenRecords   int64
}

// ProviderSessionRepository is the composite atomic persistence boundary.
// Implementations must use database-authoritative time for transitions.
type ProviderSessionRepository interface {
	Create(ctx context.Context, input ProviderSessionCreate) (ProviderSession, error)
	Resolve(ctx context.Context, lookupHash []byte, binding ProviderSessionBinding, touchInterval time.Duration) (ProviderSessionResolution, error)
	Load(ctx context.Context, sessionID string) (ProviderSessionResolution, error)
	RotateHandle(ctx context.Context, sessionID string, expectedRevision int64, oldLookupHash, newLookupHash []byte) (ProviderSession, error)
	ClaimRefresh(ctx context.Context, sessionID string, expectedRevision int64, attemptID string, lease time.Duration) (ProviderRefreshClaim, error)
	CommitRefresh(ctx context.Context, input ProviderRefreshCommit) (ProviderSession, error)
	MarkRefreshUncertain(ctx context.Context, sessionID, attemptID string, baseRevision int64, reason string) error
	ReplaceCiphertext(ctx context.Context, sessionID string, expectedRevision int64, tokens TokenEnvelope) (ProviderSession, error)
	Revoke(ctx context.Context, sessionID, reason string) (ProviderSession, bool, error)
	RevokeUser(ctx context.Context, applicationSubject, reason string) ([]ProviderSession, error)
	UpdateRemoteRevocation(ctx context.Context, sessionID string, outcome ProviderRemoteRevocationOutcome) error
	Cleanup(ctx context.Context, policy ProviderSessionCleanupPolicy) (ProviderSessionCleanupResult, error)
}

// Logical views deliberately omit create/commit operations. They are useful
// for narrow consumers while the manager retains the composite repository.
type ProviderSessionStore interface {
	Resolve(ctx context.Context, lookupHash []byte, binding ProviderSessionBinding, touchInterval time.Duration) (ProviderSessionResolution, error)
}

type ProviderTokenVault interface {
	ClaimRefresh(ctx context.Context, sessionID string, expectedRevision int64, attemptID string, lease time.Duration) (ProviderRefreshClaim, error)
	CommitRefresh(ctx context.Context, input ProviderRefreshCommit) (ProviderSession, error)
	MarkRefreshUncertain(ctx context.Context, sessionID, attemptID string, baseRevision int64, reason string) error
	ReplaceCiphertext(ctx context.Context, sessionID string, expectedRevision int64, tokens TokenEnvelope) (ProviderSession, error)
}

type ProviderRefreshRequest struct {
	Session       ProviderSession
	AttemptID     string
	RefreshToken  Secret
	CurrentTokens ProviderTokenSet
}

type ProviderRefreshResult struct {
	Tokens ProviderTokenSet
}

type ProviderTokenRefresher interface {
	RefreshProviderTokens(ctx context.Context, request ProviderRefreshRequest) (ProviderRefreshResult, error)
}

type ProviderRefreshReconcileRequest struct {
	Session      ProviderSession
	AttemptID    string
	BaseRevision int64
}

type ProviderRefreshReconcileStatus string

const (
	ProviderRefreshReconciledTokens  ProviderRefreshReconcileStatus = "tokens"
	ProviderRefreshReconciledRevoked ProviderRefreshReconcileStatus = "revoked"
	ProviderRefreshReconcileUnknown  ProviderRefreshReconcileStatus = "unknown"
)

type ProviderRefreshReconcileResult struct {
	Status ProviderRefreshReconcileStatus
	Tokens ProviderTokenSet
}

type ProviderTokenReconciler interface {
	ReconcileProviderRefresh(ctx context.Context, request ProviderRefreshReconcileRequest) (ProviderRefreshReconcileResult, error)
}

type ProviderRemoteRevocationStatus string

const (
	ProviderRemoteRevocationSucceeded   ProviderRemoteRevocationStatus = "succeeded"
	ProviderRemoteRevocationPending     ProviderRemoteRevocationStatus = "pending"
	ProviderRemoteRevocationUnsupported ProviderRemoteRevocationStatus = "unsupported"
	ProviderRemoteRevocationFailed      ProviderRemoteRevocationStatus = "failed"
)

type ProviderRemoteRevocationOutcome struct {
	Status                ProviderRemoteRevocationStatus
	Retryable             bool
	ResidualAccessExpires time.Time
}

func (o ProviderRemoteRevocationOutcome) Validate() error {
	switch o.Status {
	case ProviderRemoteRevocationSucceeded:
		if o.Retryable {
			return fmt.Errorf("%w: successful revocation cannot be retryable", ErrProviderSessionInvalid)
		}
	case ProviderRemoteRevocationUnsupported:
		if o.Retryable {
			return fmt.Errorf("%w: unsupported revocation cannot be retryable", ErrProviderSessionInvalid)
		}
	case ProviderRemoteRevocationPending:
		if !o.Retryable {
			return fmt.Errorf("%w: pending revocation must be retryable", ErrProviderSessionInvalid)
		}
	case ProviderRemoteRevocationFailed:
		// Terminal and retryable failures are both valid.
	default:
		return fmt.Errorf("%w: invalid remote revocation outcome", ErrProviderSessionInvalid)
	}
	return nil
}

type ProviderRevocationRequest struct {
	Session           ProviderSession
	Reason            string
	ReasonCode        ProviderSessionReasonCode
	ReasonFingerprint ProviderAuditFingerprint
	Tokens            ProviderTokenSet
}

type ProviderRevocationHook interface {
	RevokeProviderSession(ctx context.Context, request ProviderRevocationRequest) (ProviderRemoteRevocationOutcome, error)
}

type ProviderRemoteRevocationClaimPolicy struct {
	// Deprecated: repositories use their authoritative database clock.
	Now         time.Time
	WorkerID    string
	Lease       time.Duration
	BatchSize   int
	MaxAttempts int
}

type ProviderRemoteRevocationClaim struct {
	Session        ProviderSession
	Tokens         TokenEnvelope
	RemoteRevision int64
	Attempt        int
	LeaseOwner     string
	LeaseUntil     time.Time
	LeaseRemaining time.Duration
}

type ProviderRemoteRevocationCompletion struct {
	SessionID      string
	RemoteRevision int64
	LeaseOwner     string
	LeaseUntil     time.Time
	Outcome        ProviderRemoteRevocationOutcome
	// Deprecated: repositories derive the next attempt from their database
	// clock and RetryDelay.
	NextAttemptAt time.Time
	RetryDelay    time.Duration
	SafeErrorCode string
	Terminal      bool
}

type ProviderRemoteRevocationRepository interface {
	ClaimRemoteRevocations(
		context.Context,
		ProviderRemoteRevocationClaimPolicy,
	) ([]ProviderRemoteRevocationClaim, error)
	CompleteRemoteRevocation(context.Context, ProviderRemoteRevocationCompletion) error
}

type ProviderRemoteRevocationRetryResult struct {
	Claimed   int
	Succeeded int
	Retried   int
	Terminal  int
}

type TokenTargetCapability struct {
	id string
}

func NewTokenTargetCapability() (TokenTargetCapability, error) {
	id, err := randomProviderSessionValue(32)
	if err != nil {
		return TokenTargetCapability{}, err
	}
	return TokenTargetCapability{id: id}, nil
}

func (c TokenTargetCapability) valid() bool { return strings.TrimSpace(c.id) != "" }
func (c TokenTargetCapability) String() string {
	return "auth.TokenTargetCapability(" + redactedSecret + ")"
}
func (c TokenTargetCapability) GoString() string { return c.String() }
func (c TokenTargetCapability) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(c.String()))
}
func (c TokenTargetCapability) MarshalJSON() ([]byte, error) {
	return nil, ErrSecretSerialization
}

func randomProviderSessionValue(size int) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("%w: random value size must be positive", ErrProviderSessionInvalid)
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("%w: random source unavailable", ErrProviderSessionUnavailable)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

type TokenTarget struct {
	Name           string
	Provider       string
	Issuer         string
	ClientID       string
	Audience       string
	Resource       string
	RequiredScopes []string
	TelemetryName  string
	RequirePolicy  bool
	Capability     TokenTargetCapability
}

type TokenAccessPolicyRequest struct {
	Session ProviderSession
	Target  TokenTarget
}

type TokenAccessPolicy interface {
	AuthorizeProviderToken(ctx context.Context, request TokenAccessPolicyRequest) error
}

type UserTokenRequest struct {
	SessionHandle Secret
	Binding       ProviderSessionBinding
	Target        string
	Capability    TokenTargetCapability
}

type UserTokenProvider interface {
	AccessToken(ctx context.Context, request UserTokenRequest) (Secret, error)
}

type ProviderSessionResolver interface {
	ResolveProviderSession(ctx context.Context, handle Secret, binding ProviderSessionBinding) (ProviderSession, AuthenticatedPrincipal, error)
}

type ProviderSessionCreation struct {
	Handle    Secret
	Session   ProviderSession
	Principal AuthenticatedPrincipal
}

type ProviderSessionCreator interface {
	CreateProviderSession(ctx context.Context, principal AuthenticatedPrincipal, tokens ProviderTokenSet) (ProviderSessionCreation, error)
}

type ProviderSessionRevoker interface {
	RevokeCurrentProviderSession(ctx context.Context, handle Secret, binding ProviderSessionBinding, reason string) error
	RevokeProviderSession(ctx context.Context, sessionID, reason string) error
	RevokeUserProviderSessions(ctx context.Context, applicationSubject, reason string) error
}

// ProviderSessionLocalInvalidator makes sessions unusable without invoking a
// remote provider hook. Lifecycle coordinators use this boundary before their
// one provider-specific mutation.
type ProviderSessionLocalInvalidator interface {
	InvalidateProviderSession(ctx context.Context, sessionID, reason string) error
	InvalidateUserProviderSessions(ctx context.Context, applicationSubject, reason string) error
}

type ProviderSessionInvalidationScope struct {
	ApplicationSubject string
	TenantID           string
	SessionID          string
	// PermissionVersion installs a durable authorization fence for the
	// subject and tenant. New sessions whose principal snapshot does not
	// carry this exact version are rejected after the fence is committed.
	PermissionVersion string
	// PermissionVersionObservedAt orders duplicate/out-of-order events so an
	// older delivery cannot roll the durable fence backward.
	PermissionVersionObservedAt time.Time
}

// ProviderSessionLifecycleState is the durable session-admission state for one
// application subject and optional tenant. The empty value means "unchanged"
// on a transition; persisted fences always use one of the named values.
type ProviderSessionLifecycleState string

const (
	ProviderSessionLifecycleActive    ProviderSessionLifecycleState = "active"
	ProviderSessionLifecycleSuspended ProviderSessionLifecycleState = "suspended"
	ProviderSessionLifecycleDisabled  ProviderSessionLifecycleState = "disabled"
	ProviderSessionLifecycleArchived  ProviderSessionLifecycleState = "archived"
)

func (s ProviderSessionLifecycleState) validPersisted() bool {
	switch s {
	case ProviderSessionLifecycleActive,
		ProviderSessionLifecycleSuspended,
		ProviderSessionLifecycleDisabled,
		ProviderSessionLifecycleArchived:
		return true
	default:
		return false
	}
}

type ProviderSessionLifecycleOrdering string

const (
	// ProviderSessionLifecycleObservedOrder preserves externally observed event
	// ordering. Older or duplicate timestamps are no-ops.
	ProviderSessionLifecycleObservedOrder ProviderSessionLifecycleOrdering = "observed"
	// ProviderSessionLifecycleRepositoryOrder serializes a locally initiated
	// transition under the durable fence lock and advances generation
	// regardless of replica wall-clock skew.
	ProviderSessionLifecycleRepositoryOrder ProviderSessionLifecycleOrdering = "repository"
)

// ProviderSessionLifecycleTransition advances a durable lifecycle fence.
// BlockedState may be empty to leave the account state unchanged. An explicit
// active state is the only transition that clears a prior block.
type ProviderSessionLifecycleTransition struct {
	ApplicationSubject    string
	TenantID              string
	BlockedState          ProviderSessionLifecycleState
	CredentialsNotBefore  time.Time
	AdvanceCredentials    bool
	EventObservedAt       time.Time
	Reason                string
	Ordering              ProviderSessionLifecycleOrdering
	QueueRemoteRevocation bool
}

func (t ProviderSessionLifecycleTransition) Validate() error {
	if strings.TrimSpace(t.ApplicationSubject) == "" {
		return ErrProviderSessionInvalid
	}
	switch t.Ordering {
	case "":
		if t.EventObservedAt.IsZero() {
			return ErrProviderSessionInvalid
		}
	case ProviderSessionLifecycleObservedOrder:
		if t.EventObservedAt.IsZero() {
			return ErrProviderSessionInvalid
		}
	case ProviderSessionLifecycleRepositoryOrder:
	default:
		return ErrProviderSessionInvalid
	}
	if t.BlockedState != "" && !t.BlockedState.validPersisted() {
		return ErrProviderSessionInvalid
	}
	if t.BlockedState == "" && t.CredentialsNotBefore.IsZero() && !t.AdvanceCredentials {
		return ErrProviderSessionInvalid
	}
	return nil
}

// ProviderSessionLifecycleFence is the observable non-secret lifecycle state.
type ProviderSessionLifecycleFence struct {
	ApplicationSubject   string
	TenantID             string
	BlockedState         ProviderSessionLifecycleState
	CredentialsNotBefore time.Time
	EventObservedAt      time.Time
	Generation           int64
}

// ProviderSessionLifecycleRepository is the additive durable capability used
// by hardened lifecycle coordination and provider-session admission.
type ProviderSessionLifecycleRepository interface {
	AdvanceProviderSessionLifecycle(
		ctx context.Context,
		transition ProviderSessionLifecycleTransition,
	) (fence ProviderSessionLifecycleFence, revoked []ProviderSession, err error)
}

type ProviderSessionLifecycleInvalidator interface {
	ApplyProviderSessionLifecycle(
		ctx context.Context,
		transition ProviderSessionLifecycleTransition,
	) (fence ProviderSessionLifecycleFence, revoked []ProviderSession, err error)
}

type ProviderSessionScopeRepository interface {
	RevokeScope(
		ctx context.Context,
		scope ProviderSessionInvalidationScope,
		limit int,
		reason string,
	) (sessions []ProviderSession, more bool, err error)
}

type ProviderSessionScopeInvalidator interface {
	InvalidateProviderSessions(
		ctx context.Context,
		scope ProviderSessionInvalidationScope,
		limit int,
		reason string,
	) (invalidated int, more bool, err error)
}

type StateStoreMaintenance interface {
	CleanupExpired(ctx context.Context, before time.Time, limit int) (int64, error)
}
