package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
)

type ProviderSessionModel struct {
	bun.BaseModel `bun:"table:provider_sessions"`

	ID                            string          `bun:"id,pk,type:uuid"`
	LocalSessionID                string          `bun:"local_session_id,notnull,type:uuid"`
	LookupHash                    []byte          `bun:"lookup_hash,notnull"`
	ApplicationSubject            string          `bun:"application_subject,notnull"`
	ProviderSubject               string          `bun:"provider_subject,notnull"`
	ProviderSessionID             string          `bun:"provider_session_id"`
	Host                          string          `bun:"host,notnull"`
	ApplicationID                 string          `bun:"application_id,notnull"`
	Environment                   string          `bun:"environment,notnull"`
	TenantID                      string          `bun:"tenant_id,notnull"`
	Provider                      string          `bun:"provider,notnull"`
	Issuer                        string          `bun:"issuer,notnull"`
	OAuthClientID                 string          `bun:"oauth_client_id,notnull"`
	Principal                     json.RawMessage `bun:"principal,type:jsonb,notnull"`
	Status                        string          `bun:"status,notnull"`
	TokenRevision                 int64           `bun:"token_revision,notnull"`
	CreatedAt                     time.Time       `bun:"created_at,nullzero,notnull,default:current_timestamp"`
	LastSeenAt                    time.Time       `bun:"last_seen_at,nullzero,notnull,default:current_timestamp"`
	IdleExpiresAt                 time.Time       `bun:"idle_expires_at,notnull"`
	MaxExpiresAt                  time.Time       `bun:"max_expires_at,notnull"`
	RefreshAttemptID              *string         `bun:"refresh_attempt_id"`
	RefreshBaseRevision           *int64          `bun:"refresh_base_revision"`
	RefreshLeaseUntil             *time.Time      `bun:"refresh_lease_until"`
	RevokedAt                     *time.Time      `bun:"revoked_at"`
	RevocationReason              string          `bun:"revocation_reason"`
	RevocationReasonFingerprint   string          `bun:"revocation_reason_fingerprint"`
	RemoteRevocationStatus        string          `bun:"remote_revocation_status"`
	RemoteRevocationRetryable     bool            `bun:"remote_revocation_retryable,notnull"`
	ResidualAccessExpiresAt       *time.Time      `bun:"residual_access_expires_at"`
	RemoteRevocationAttemptCount  int             `bun:"remote_revocation_attempt_count,notnull"`
	RemoteRevocationNextAttemptAt *time.Time      `bun:"remote_revocation_next_attempt_at"`
	RemoteRevocationLeaseOwner    string          `bun:"remote_revocation_lease_owner"`
	RemoteRevocationLeaseUntil    *time.Time      `bun:"remote_revocation_lease_until"`
	RemoteRevocationRevision      int64           `bun:"remote_revocation_revision,notnull"`
	RemoteRevocationSafeErrorCode string          `bun:"remote_revocation_safe_error_code"`
	RemoteRevocationWorkExpiresAt *time.Time      `bun:"remote_revocation_work_expires_at"`
	RemoteRevocationTerminalAt    *time.Time      `bun:"remote_revocation_terminal_at"`
	UpdatedAt                     time.Time       `bun:"updated_at,nullzero,notnull,default:current_timestamp"`
}

type ProviderSessionTokenModel struct {
	bun.BaseModel `bun:"table:provider_session_tokens"`

	SessionID         string     `bun:"session_id,pk,type:uuid"`
	TokenRevision     int64      `bun:"token_revision,notnull"`
	EnvelopeVersion   uint8      `bun:"envelope_version,notnull"`
	EnvelopeAlgorithm string     `bun:"envelope_algorithm,notnull"`
	KeyID             string     `bun:"key_id,notnull"`
	Nonce             []byte     `bun:"nonce,notnull"`
	Ciphertext        []byte     `bun:"ciphertext,notnull"`
	AccessExpiresAt   *time.Time `bun:"access_expires_at"`
	RefreshExpiresAt  *time.Time `bun:"refresh_expires_at"`
	RetainUntil       *time.Time `bun:"retain_until"`
	CreatedAt         time.Time  `bun:"created_at,nullzero,notnull,default:current_timestamp"`
	UpdatedAt         time.Time  `bun:"updated_at,nullzero,notnull,default:current_timestamp"`
}

type ProviderSessionAuthorizationFenceModel struct {
	bun.BaseModel `bun:"table:provider_session_authorization_fences"`

	ApplicationSubject          string     `bun:"application_subject,pk,notnull"`
	TenantID                    string     `bun:"tenant_id,pk,notnull"`
	RequiredPermissionVersion   string     `bun:"required_permission_version,notnull"`
	PermissionVersionObservedAt *time.Time `bun:"permission_version_observed_at"`
	CreatedAt                   time.Time  `bun:"created_at,nullzero,notnull,default:current_timestamp"`
	UpdatedAt                   time.Time  `bun:"updated_at,nullzero,notnull,default:current_timestamp"`
}

type ProviderSessionRepository struct {
	db *bun.DB
}

func NewProviderSessionRepository(db *bun.DB) (*ProviderSessionRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: database is required", auth.ErrProviderSessionUnavailable)
	}
	return &ProviderSessionRepository{db: db}, nil
}

func (r *ProviderSessionRepository) Create(ctx context.Context, input auth.ProviderSessionCreate) (auth.ProviderSession, error) {
	if r == nil || r.db == nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionUnavailable
	}
	sessionModel, tokenModel, err := providerSessionCreateModels(input)
	if err != nil {
		return auth.ProviderSession{}, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return auth.ProviderSession{}, fmt.Errorf("%w: begin create", auth.ErrProviderSessionUnavailable)
	}
	defer func() { _ = tx.Rollback() }()
	dbNow, err := databaseTime(ctx, tx)
	if err != nil {
		return auth.ProviderSession{}, fmt.Errorf("%w: database time unavailable", auth.ErrProviderSessionUnavailable)
	}
	idleWindow := input.Session.IdleExpiresAt.Sub(input.Session.CreatedAt)
	maxWindow := input.Session.MaxExpiresAt.Sub(input.Session.CreatedAt)
	if idleWindow <= 0 || maxWindow <= 0 || idleWindow > maxWindow {
		return auth.ProviderSession{}, auth.ErrProviderSessionInvalid
	}
	sessionModel.CreatedAt = dbNow
	sessionModel.LastSeenAt = dbNow
	sessionModel.IdleExpiresAt = dbNow.Add(idleWindow)
	sessionModel.MaxExpiresAt = dbNow.Add(maxWindow)
	if err := lockProviderSessionAuthorizationFence(
		ctx,
		tx,
		r.db.Dialect().Name(),
		sessionModel.ApplicationSubject,
		sessionModel.TenantID,
		input.Session.Principal.PermissionVersion,
		input.Session.Principal.IssuedAt,
	); err != nil {
		return auth.ProviderSession{}, err
	}
	if _, err := tx.NewInsert().Model(sessionModel).Exec(ctx); err != nil {
		return auth.ProviderSession{}, fmt.Errorf("%w: create session", auth.ErrProviderSessionUnavailable)
	}
	if _, err := tx.NewInsert().Model(tokenModel).Exec(ctx); err != nil {
		return auth.ProviderSession{}, fmt.Errorf("%w: create tokens", auth.ErrProviderSessionUnavailable)
	}
	if err := tx.Commit(); err != nil {
		return auth.ProviderSession{}, fmt.Errorf("%w: commit create", auth.ErrProviderSessionUnavailable)
	}
	return sessionFromModel(sessionModel)
}

//nolint:gocyclo,funlen // Transactional status, expiry, lease, and touch transitions remain explicit.
func (r *ProviderSessionRepository) Resolve(ctx context.Context, lookupHash []byte, binding auth.ProviderSessionBinding, touchInterval time.Duration) (auth.ProviderSessionResolution, error) {
	if r == nil || r.db == nil || len(lookupHash) != sha256Size {
		return auth.ProviderSessionResolution{}, auth.ErrProviderSessionNotFound
	}
	if err := binding.Validate(); err != nil {
		return auth.ProviderSessionResolution{}, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return auth.ProviderSessionResolution{}, auth.ErrProviderSessionUnavailable
	}
	defer func() { _ = tx.Rollback() }()

	model, err := selectProviderSession(ctx, tx, r.db.Dialect().Name(), "lookup_hash = ?", lookupHash)
	if err != nil {
		return auth.ProviderSessionResolution{}, err
	}
	session, err := sessionFromModel(model)
	if err != nil {
		return auth.ProviderSessionResolution{}, err
	}
	if !session.Binding.Equal(binding) {
		return auth.ProviderSessionResolution{}, auth.ErrProviderSessionBinding
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return auth.ProviderSessionResolution{}, auth.ErrProviderSessionUnavailable
	}
	if session.Status == auth.ProviderSessionRefreshing && !session.RefreshLeaseUntil.IsZero() && !now.Before(session.RefreshLeaseUntil) {
		if _, updateErr := tx.NewUpdate().Model((*ProviderSessionModel)(nil)).
			Set("status = ?", auth.ProviderSessionUncertain).
			Set("updated_at = ?", now).
			Where("id = ? AND status = ? AND refresh_attempt_id = ?", session.ID, auth.ProviderSessionRefreshing, session.RefreshAttemptID).
			Exec(ctx); updateErr != nil {
			return auth.ProviderSessionResolution{}, auth.ErrProviderSessionUnavailable
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return auth.ProviderSessionResolution{}, auth.ErrProviderSessionUnavailable
		}
		return auth.ProviderSessionResolution{}, auth.ErrProviderSessionUncertain
	}
	if !session.Status.Usable() {
		return auth.ProviderSessionResolution{}, statusError(session.Status)
	}
	if !now.Before(session.MaxExpiresAt) || !now.Before(session.IdleExpiresAt) {
		if _, updateErr := tx.NewUpdate().Model((*ProviderSessionModel)(nil)).
			Set("status = ?", auth.ProviderSessionExpired).
			Set("updated_at = ?", now).
			Where("id = ? AND status = ?", session.ID, auth.ProviderSessionAvailable).
			Exec(ctx); updateErr != nil {
			return auth.ProviderSessionResolution{}, auth.ErrProviderSessionUnavailable
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return auth.ProviderSessionResolution{}, auth.ErrProviderSessionUnavailable
		}
		return auth.ProviderSessionResolution{}, auth.ErrProviderSessionExpired
	}
	if touchInterval <= 0 {
		touchInterval = auth.DefaultProviderSessionTouch
	}
	if !now.Before(session.LastSeenAt.Add(touchInterval)) {
		idleWindow := session.IdleExpiresAt.Sub(session.LastSeenAt)
		nextIdle := now.Add(idleWindow)
		if nextIdle.After(session.MaxExpiresAt) {
			nextIdle = session.MaxExpiresAt
		}
		result, updateErr := tx.NewUpdate().Model((*ProviderSessionModel)(nil)).
			Set("last_seen_at = ?", now).
			Set("idle_expires_at = ?", nextIdle).
			Set("updated_at = ?", now).
			Where("id = ? AND status = ? AND last_seen_at = ? AND token_revision = ?",
				session.ID, auth.ProviderSessionAvailable, session.LastSeenAt, session.TokenRevision).
			Exec(ctx)
		if updateErr != nil {
			return auth.ProviderSessionResolution{}, auth.ErrProviderSessionUnavailable
		}
		affected, _ := result.RowsAffected()
		if affected == 1 {
			session.LastSeenAt = now
			session.IdleExpiresAt = nextIdle
		}
	}
	tokens, err := selectProviderSessionTokens(ctx, tx, session.ID)
	if err != nil {
		return auth.ProviderSessionResolution{}, err
	}
	if tokens.TokenRevision != session.TokenRevision {
		return auth.ProviderSessionResolution{}, auth.ErrProviderSessionConflict
	}
	if err := tx.Commit(); err != nil {
		return auth.ProviderSessionResolution{}, auth.ErrProviderSessionUnavailable
	}
	return auth.ProviderSessionResolution{Session: session, Tokens: tokenEnvelopeFromModel(tokens)}, nil
}

func (r *ProviderSessionRepository) Load(ctx context.Context, sessionID string) (auth.ProviderSessionResolution, error) {
	if r == nil || r.db == nil || strings.TrimSpace(sessionID) == "" {
		return auth.ProviderSessionResolution{}, auth.ErrProviderSessionNotFound
	}
	model, err := selectProviderSession(ctx, r.db, r.db.Dialect().Name(), "id = ?", sessionID)
	if err != nil {
		return auth.ProviderSessionResolution{}, err
	}
	session, err := sessionFromModel(model)
	if err != nil {
		return auth.ProviderSessionResolution{}, err
	}
	tokens, err := selectProviderSessionTokens(ctx, r.db, sessionID)
	if err != nil {
		return auth.ProviderSessionResolution{}, err
	}
	if tokens.TokenRevision != session.TokenRevision {
		return auth.ProviderSessionResolution{}, auth.ErrProviderSessionConflict
	}
	return auth.ProviderSessionResolution{Session: session, Tokens: tokenEnvelopeFromModel(tokens)}, nil
}

func (r *ProviderSessionRepository) RotateHandle(ctx context.Context, sessionID string, expectedRevision int64, oldLookupHash, newLookupHash []byte) (auth.ProviderSession, error) {
	if len(oldLookupHash) != sha256Size || len(newLookupHash) != sha256Size {
		return auth.ProviderSession{}, auth.ErrProviderSessionInvalid
	}
	result, err := r.db.NewUpdate().Model((*ProviderSessionModel)(nil)).
		Set("lookup_hash = ?", newLookupHash).
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("id = ? AND lookup_hash = ? AND token_revision = ? AND status = ?",
			sessionID, oldLookupHash, expectedRevision, auth.ProviderSessionAvailable).
		Exec(ctx)
	if err != nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionUnavailable
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return auth.ProviderSession{}, auth.ErrProviderSessionConflict
	}
	return r.sessionByID(ctx, sessionID)
}

func (r *ProviderSessionRepository) ClaimRefresh(ctx context.Context, sessionID string, expectedRevision int64, attemptID string, lease time.Duration) (auth.ProviderRefreshClaim, error) {
	if strings.TrimSpace(attemptID) == "" || lease < 5*time.Second || lease > 2*time.Minute {
		return auth.ProviderRefreshClaim{}, auth.ErrProviderSessionInvalid
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return auth.ProviderRefreshClaim{}, auth.ErrProviderSessionUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	model, err := selectProviderSession(ctx, tx, r.db.Dialect().Name(), "id = ?", sessionID)
	if err != nil {
		return auth.ProviderRefreshClaim{}, err
	}
	session, err := sessionFromModel(model)
	if err != nil {
		return auth.ProviderRefreshClaim{}, err
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return auth.ProviderRefreshClaim{}, auth.ErrProviderSessionUnavailable
	}
	if session.TokenRevision != expectedRevision {
		return auth.ProviderRefreshClaim{}, auth.ErrProviderSessionConflict
	}
	if session.Status == auth.ProviderSessionRefreshing {
		return claimRefreshingProviderSession(ctx, tx, session, attemptID, now)
	}
	if !session.Status.Usable() {
		return auth.ProviderRefreshClaim{}, statusError(session.Status)
	}
	leaseUntil := now.Add(lease)
	result, err := tx.NewUpdate().Model((*ProviderSessionModel)(nil)).
		Set("status = ?", auth.ProviderSessionRefreshing).
		Set("refresh_attempt_id = ?", attemptID).
		Set("refresh_base_revision = ?", expectedRevision).
		Set("refresh_lease_until = ?", leaseUntil).
		Set("updated_at = ?", now).
		Where("id = ? AND status = ? AND token_revision = ?", session.ID, auth.ProviderSessionAvailable, expectedRevision).
		Exec(ctx)
	if err != nil {
		return auth.ProviderRefreshClaim{}, auth.ErrProviderSessionUnavailable
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return auth.ProviderRefreshClaim{}, auth.ErrProviderSessionConflict
	}
	tokens, err := selectProviderSessionTokens(ctx, tx, session.ID)
	if err != nil {
		return auth.ProviderRefreshClaim{}, err
	}
	if err := tx.Commit(); err != nil {
		return auth.ProviderRefreshClaim{}, auth.ErrProviderSessionUnavailable
	}
	session.Status = auth.ProviderSessionRefreshing
	session.RefreshAttemptID = attemptID
	session.RefreshBaseRevision = expectedRevision
	session.RefreshLeaseUntil = leaseUntil
	return auth.ProviderRefreshClaim{Session: session, Tokens: tokenEnvelopeFromModel(tokens), AttemptID: attemptID, Acquired: true}, nil
}

func claimRefreshingProviderSession(
	ctx context.Context,
	tx bun.Tx,
	session auth.ProviderSession,
	attemptID string,
	now time.Time,
) (auth.ProviderRefreshClaim, error) {
	if session.RefreshAttemptID == attemptID {
		tokens, err := selectProviderSessionTokens(ctx, tx, session.ID)
		if err != nil {
			return auth.ProviderRefreshClaim{}, err
		}
		return auth.ProviderRefreshClaim{
			Session: session, Tokens: tokenEnvelopeFromModel(tokens),
			AttemptID: attemptID, Acquired: true,
		}, nil
	}
	if now.Before(session.RefreshLeaseUntil) {
		return auth.ProviderRefreshClaim{
			Session: session, AttemptID: session.RefreshAttemptID, Acquired: false,
		}, nil
	}
	if _, err := tx.NewUpdate().Model((*ProviderSessionModel)(nil)).
		Set("status = ?", auth.ProviderSessionUncertain).
		Set("updated_at = ?", now).
		Where(
			"id = ? AND status = ? AND refresh_attempt_id = ?",
			session.ID,
			auth.ProviderSessionRefreshing,
			session.RefreshAttemptID,
		).
		Exec(ctx); err != nil {
		return auth.ProviderRefreshClaim{}, auth.ErrProviderSessionUnavailable
	}
	if err := tx.Commit(); err != nil {
		return auth.ProviderRefreshClaim{}, auth.ErrProviderSessionUnavailable
	}
	return auth.ProviderRefreshClaim{}, auth.ErrProviderSessionUncertain
}

func (r *ProviderSessionRepository) CommitRefresh(ctx context.Context, input auth.ProviderRefreshCommit) (auth.ProviderSession, error) {
	if strings.TrimSpace(input.SessionID) == "" || strings.TrimSpace(input.AttemptID) == "" || input.BaseRevision <= 0 {
		return auth.ProviderSession{}, auth.ErrProviderSessionInvalid
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionUnavailable
	}
	nextRevision := input.BaseRevision + 1
	tokenResult, err := tx.NewUpdate().Model((*ProviderSessionTokenModel)(nil)).
		Set("token_revision = ?", nextRevision).
		Set("envelope_version = ?", input.Tokens.Version).
		Set("envelope_algorithm = ?", input.Tokens.Algorithm).
		Set("key_id = ?", input.Tokens.KeyID).
		Set("nonce = ?", input.Tokens.Nonce).
		Set("ciphertext = ?", input.Tokens.Ciphertext).
		Set("access_expires_at = ?", nullableTime(input.AccessExpiresAt)).
		Set("refresh_expires_at = ?", nullableTime(input.RefreshExpiresAt)).
		Set("updated_at = ?", now).
		Where("session_id = ? AND token_revision = ?", input.SessionID, input.BaseRevision).
		Exec(ctx)
	if err != nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionUnavailable
	}
	if affected, _ := tokenResult.RowsAffected(); affected != 1 {
		return auth.ProviderSession{}, auth.ErrProviderSessionConflict
	}
	sessionResult, err := tx.NewUpdate().Model((*ProviderSessionModel)(nil)).
		Set("status = ?", auth.ProviderSessionAvailable).
		Set("token_revision = ?", nextRevision).
		Set("refresh_attempt_id = NULL").
		Set("refresh_base_revision = NULL").
		Set("refresh_lease_until = NULL").
		Set("updated_at = ?", now).
		Where("id = ? AND status = ? AND token_revision = ? AND refresh_attempt_id = ?",
			input.SessionID, auth.ProviderSessionRefreshing, input.BaseRevision, input.AttemptID).
		Exec(ctx)
	if err != nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionUnavailable
	}
	if affected, _ := sessionResult.RowsAffected(); affected != 1 {
		return auth.ProviderSession{}, auth.ErrProviderSessionConflict
	}
	if err := tx.Commit(); err != nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionUnavailable
	}
	return r.sessionByID(ctx, input.SessionID)
}

func (r *ProviderSessionRepository) MarkRefreshUncertain(ctx context.Context, sessionID, attemptID string, baseRevision int64, reason string) error {
	result, err := r.db.NewUpdate().Model((*ProviderSessionModel)(nil)).
		Set("status = ?", auth.ProviderSessionUncertain).
		Set("revocation_reason = ?", boundedReason(reason)).
		Set("refresh_lease_until = NULL").
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("id = ? AND status = ? AND token_revision = ? AND refresh_attempt_id = ?",
			sessionID, auth.ProviderSessionRefreshing, baseRevision, attemptID).
		Exec(ctx)
	if err != nil {
		return auth.ErrProviderSessionUnavailable
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return auth.ErrProviderSessionConflict
	}
	return nil
}

func (r *ProviderSessionRepository) ReplaceCiphertext(ctx context.Context, sessionID string, expectedRevision int64, envelope auth.TokenEnvelope) (auth.ProviderSession, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionUnavailable
	}
	nextRevision := expectedRevision + 1
	tokenResult, err := tx.NewUpdate().Model((*ProviderSessionTokenModel)(nil)).
		Set("token_revision = ?", nextRevision).
		Set("envelope_version = ?", envelope.Version).
		Set("envelope_algorithm = ?", envelope.Algorithm).
		Set("key_id = ?", envelope.KeyID).
		Set("nonce = ?", envelope.Nonce).
		Set("ciphertext = ?", envelope.Ciphertext).
		Set("updated_at = ?", now).
		Where("session_id = ? AND token_revision = ?", sessionID, expectedRevision).
		Exec(ctx)
	if err != nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionUnavailable
	}
	if affected, _ := tokenResult.RowsAffected(); affected != 1 {
		return auth.ProviderSession{}, auth.ErrProviderSessionConflict
	}
	sessionResult, err := tx.NewUpdate().Model((*ProviderSessionModel)(nil)).
		Set("token_revision = ?", nextRevision).
		Set("updated_at = ?", now).
		Where("id = ? AND status = ? AND token_revision = ?", sessionID, auth.ProviderSessionAvailable, expectedRevision).
		Exec(ctx)
	if err != nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionUnavailable
	}
	if affected, _ := sessionResult.RowsAffected(); affected != 1 {
		return auth.ProviderSession{}, auth.ErrProviderSessionConflict
	}
	if err := tx.Commit(); err != nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionUnavailable
	}
	return r.sessionByID(ctx, sessionID)
}

func (r *ProviderSessionRepository) Revoke(ctx context.Context, sessionID, reason string) (auth.ProviderSession, bool, error) {
	now, err := databaseTime(ctx, r.db)
	if err != nil {
		return auth.ProviderSession{}, false, auth.ErrProviderSessionUnavailable
	}
	result, err := r.db.NewUpdate().Model((*ProviderSessionModel)(nil)).
		Set("status = ?", auth.ProviderSessionRevoked).
		Set("revoked_at = COALESCE(revoked_at, ?)", now).
		Set("revocation_reason = CASE WHEN revocation_reason = '' THEN ? ELSE revocation_reason END", boundedReason(reason)).
		Set("refresh_lease_until = NULL").
		Set("updated_at = ?", now).
		Where("id = ? AND status NOT IN (?, ?)", sessionID, auth.ProviderSessionRevoked, auth.ProviderSessionExpired).
		Exec(ctx)
	if err != nil {
		return auth.ProviderSession{}, false, auth.ErrProviderSessionUnavailable
	}
	affected, _ := result.RowsAffected()
	session, lookupErr := r.sessionByID(ctx, sessionID)
	if lookupErr != nil {
		return auth.ProviderSession{}, false, lookupErr
	}
	return session, affected == 1, nil
}

func (r *ProviderSessionRepository) RevokeUser(ctx context.Context, applicationSubject, reason string) ([]auth.ProviderSession, error) {
	applicationSubject = strings.TrimSpace(applicationSubject)
	if applicationSubject == "" {
		return nil, auth.ErrProviderSessionInvalid
	}
	now, err := databaseTime(ctx, r.db)
	if err != nil {
		return nil, auth.ErrProviderSessionUnavailable
	}
	var models []ProviderSessionModel
	if err := r.db.NewSelect().Model(&models).
		Where("application_subject = ? AND status NOT IN (?, ?)", applicationSubject, auth.ProviderSessionRevoked, auth.ProviderSessionExpired).
		Scan(ctx); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, auth.ErrProviderSessionUnavailable
	}
	if len(models) == 0 {
		return []auth.ProviderSession{}, nil
	}
	if _, err := r.db.NewUpdate().Model((*ProviderSessionModel)(nil)).
		Set("status = ?", auth.ProviderSessionRevoked).
		Set("revoked_at = COALESCE(revoked_at, ?)", now).
		Set("revocation_reason = CASE WHEN revocation_reason = '' THEN ? ELSE revocation_reason END", boundedReason(reason)).
		Set("refresh_lease_until = NULL").
		Set("updated_at = ?", now).
		Where("application_subject = ? AND status NOT IN (?, ?)", applicationSubject, auth.ProviderSessionRevoked, auth.ProviderSessionExpired).
		Exec(ctx); err != nil {
		return nil, auth.ErrProviderSessionUnavailable
	}
	out := make([]auth.ProviderSession, 0, len(models))
	for i := range models {
		models[i].Status = string(auth.ProviderSessionRevoked)
		models[i].RevokedAt = &now
		session, convertErr := sessionFromModel(&models[i])
		if convertErr != nil {
			return nil, convertErr
		}
		out = append(out, session)
	}
	return out, nil
}

//nolint:gocyclo // Bounded scope filtering and transactional revocation remain explicit.
func (r *ProviderSessionRepository) RevokeScope(
	ctx context.Context,
	scope auth.ProviderSessionInvalidationScope,
	limit int,
	reason string,
) ([]auth.ProviderSession, bool, error) {
	if r == nil || r.db == nil || limit <= 0 || limit > 10_000 {
		return nil, false, auth.ErrProviderSessionInvalid
	}
	scope.ApplicationSubject = strings.TrimSpace(scope.ApplicationSubject)
	scope.TenantID = strings.TrimSpace(scope.TenantID)
	scope.SessionID = strings.TrimSpace(scope.SessionID)
	scope.PermissionVersion = strings.TrimSpace(scope.PermissionVersion)
	if scope.ApplicationSubject == "" && scope.TenantID == "" && scope.SessionID == "" {
		return nil, false, auth.ErrProviderSessionInvalid
	}
	if scope.PermissionVersion != "" &&
		(scope.ApplicationSubject == "" || scope.PermissionVersionObservedAt.IsZero()) {
		return nil, false, auth.ErrProviderSessionInvalid
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, false, auth.ErrProviderSessionUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if scope.PermissionVersion != "" {
		if err := advanceProviderSessionAuthorizationFence(
			ctx,
			tx,
			scope.ApplicationSubject,
			scope.TenantID,
			scope.PermissionVersion,
			scope.PermissionVersionObservedAt,
			r.db.Dialect().Name(),
		); err != nil {
			return nil, false, err
		}
	}
	var models []ProviderSessionModel
	query := tx.NewSelect().Model(&models).
		Where("status NOT IN (?, ?)", auth.ProviderSessionRevoked, auth.ProviderSessionExpired).
		Order("id ASC").
		Limit(limit + 1)
	if r.db.Dialect().Name() == dialect.PG {
		query = query.For("UPDATE")
	}
	if scope.ApplicationSubject != "" {
		query = query.Where("application_subject = ?", scope.ApplicationSubject)
	}
	if scope.TenantID != "" {
		query = query.Where("tenant_id = ?", scope.TenantID)
	}
	if scope.SessionID != "" {
		query = query.Where("id = ?", scope.SessionID)
	}
	if err := query.Scan(ctx); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, false, auth.ErrProviderSessionUnavailable
	}
	more := len(models) > limit
	if more {
		models = models[:limit]
	}
	if len(models) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, false, auth.ErrProviderSessionUnavailable
		}
		return []auth.ProviderSession{}, false, nil
	}
	ids := make([]string, 0, len(models))
	for index := range models {
		ids = append(ids, models[index].ID)
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return nil, false, auth.ErrProviderSessionUnavailable
	}
	if _, err := tx.NewUpdate().Model((*ProviderSessionModel)(nil)).
		Set("status = ?", auth.ProviderSessionRevoked).
		Set("revoked_at = COALESCE(revoked_at, ?)", now).
		Set("revocation_reason = CASE WHEN revocation_reason = '' THEN ? ELSE revocation_reason END", boundedReason(reason)).
		Set("refresh_lease_until = NULL").
		Set("updated_at = ?", now).
		Where("id IN (?) AND status NOT IN (?, ?)", bun.In(ids), auth.ProviderSessionRevoked, auth.ProviderSessionExpired).
		Exec(ctx); err != nil {
		return nil, false, auth.ErrProviderSessionUnavailable
	}
	if err := tx.Commit(); err != nil {
		return nil, false, auth.ErrProviderSessionUnavailable
	}
	out := make([]auth.ProviderSession, 0, len(models))
	for index := range models {
		models[index].Status = string(auth.ProviderSessionRevoked)
		models[index].RevokedAt = &now
		session, convertErr := sessionFromModel(&models[index])
		if convertErr != nil {
			return nil, false, convertErr
		}
		out = append(out, session)
	}
	return out, more, nil
}

var _ auth.ProviderSessionScopeRepository = (*ProviderSessionRepository)(nil)

func (r *ProviderSessionRepository) UpdateRemoteRevocation(ctx context.Context, sessionID string, outcome auth.ProviderRemoteRevocationOutcome) error {
	result, err := r.db.NewUpdate().Model((*ProviderSessionModel)(nil)).
		Set("remote_revocation_status = ?", outcome.Status).
		Set("remote_revocation_retryable = ?", outcome.Retryable).
		Set("residual_access_expires_at = ?", nullableTime(outcome.ResidualAccessExpires)).
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("id = ? AND status = ?", sessionID, auth.ProviderSessionRevoked).
		Exec(ctx)
	if err != nil {
		return auth.ErrProviderSessionUnavailable
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return auth.ErrProviderSessionConflict
	}
	if !retryable {
		if _, err := tx.NewDelete().
			Model((*ProviderSessionTokenModel)(nil)).
			Where("session_id = ?", sessionID).
			Exec(ctx); err != nil {
			return auth.ErrProviderSessionUnavailable
		}
	}
	if err := tx.Commit(); err != nil {
		return auth.ErrProviderSessionUnavailable
	}
	return nil
}

func (r *ProviderSessionRepository) ClaimRemoteRevocations(
	ctx context.Context,
	policy auth.ProviderRemoteRevocationClaimPolicy,
) ([]auth.ProviderRemoteRevocationClaim, error) {
	if r == nil || r.db == nil {
		return nil, auth.ErrProviderSessionUnavailable
	}
	if policy.Now.IsZero() {
		var err error
		policy.Now, err = databaseTime(ctx, r.db)
		if err != nil {
			return nil, auth.ErrProviderSessionUnavailable
		}
	}
	policy.WorkerID = strings.TrimSpace(policy.WorkerID)
	if policy.Lease <= 0 {
		policy.Lease = 30 * time.Second
	}
	if policy.BatchSize <= 0 {
		policy.BatchSize = 100
	}
	if policy.MaxAttempts <= 0 {
		policy.MaxAttempts = 10
	}
	if policy.WorkerID == "" || policy.Lease < 5*time.Second || policy.Lease > 5*time.Minute ||
		policy.BatchSize > 10_000 || policy.MaxAttempts > 100 {
		return nil, auth.ErrProviderSessionInvalid
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, auth.ErrProviderSessionUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	var models []ProviderSessionModel
	query := tx.NewSelect().
		Model(&models).
		Where("status = ? AND remote_revocation_retryable = TRUE", auth.ProviderSessionRevoked).
		Where("(remote_revocation_next_attempt_at IS NULL OR remote_revocation_next_attempt_at <= ?)", policy.Now.UTC()).
		Where("(remote_revocation_lease_until IS NULL OR remote_revocation_lease_until <= ?)", policy.Now.UTC()).
		Where("(remote_revocation_work_expires_at IS NULL OR remote_revocation_work_expires_at > ?)", policy.Now.UTC()).
		Where("remote_revocation_attempt_count < ?", policy.MaxAttempts).
		Order("remote_revocation_next_attempt_at ASC NULLS FIRST", "id ASC").
		Limit(policy.BatchSize)
	if r.db.Dialect().Name() == dialect.PG {
		query = query.For("UPDATE SKIP LOCKED")
	}
	if err := query.Scan(ctx); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, auth.ErrProviderSessionUnavailable
	}
	claims := make([]auth.ProviderRemoteRevocationClaim, 0, len(models))
	for index := range models {
		model := &models[index]
		tokens, tokenErr := selectProviderSessionTokens(ctx, tx, model.ID)
		if tokenErr != nil {
			_, _ = tx.NewUpdate().
				Model((*ProviderSessionModel)(nil)).
				Set("remote_revocation_retryable = FALSE").
				Set("remote_revocation_status = ?", auth.ProviderRemoteRevocationFailed).
				Set("remote_revocation_safe_error_code = ?", "ciphertext_unavailable").
				Set("remote_revocation_terminal_at = ?", policy.Now.UTC()).
				Set("updated_at = ?", policy.Now.UTC()).
				Where("id = ? AND remote_revocation_revision = ?", model.ID, model.RemoteRevocationRevision).
				Exec(ctx)
			continue
		}
		leaseUntil := policy.Now.UTC().Add(policy.Lease)
		result, updateErr := tx.NewUpdate().
			Model((*ProviderSessionModel)(nil)).
			Set("remote_revocation_lease_owner = ?", policy.WorkerID).
			Set("remote_revocation_lease_until = ?", leaseUntil).
			Set("remote_revocation_attempt_count = remote_revocation_attempt_count + 1").
			Set("remote_revocation_revision = remote_revocation_revision + 1").
			Set("updated_at = ?", policy.Now.UTC()).
			Where("id = ? AND remote_revocation_revision = ?", model.ID, model.RemoteRevocationRevision).
			Exec(ctx)
		if updateErr != nil {
			return nil, auth.ErrProviderSessionUnavailable
		}
		affected, _ := result.RowsAffected()
		if affected != 1 {
			continue
		}
		model.RemoteRevocationLeaseOwner = policy.WorkerID
		model.RemoteRevocationLeaseUntil = &leaseUntil
		model.RemoteRevocationAttemptCount++
		model.RemoteRevocationRevision++
		session, convertErr := sessionFromModel(model)
		if convertErr != nil {
			return nil, convertErr
		}
		claims = append(claims, auth.ProviderRemoteRevocationClaim{
			Session:        session,
			Tokens:         tokenEnvelopeFromModel(tokens),
			RemoteRevision: model.RemoteRevocationRevision,
			Attempt:        model.RemoteRevocationAttemptCount,
		})
	}
	if err := tx.Commit(); err != nil {
		return nil, auth.ErrProviderSessionUnavailable
	}
	return claims, nil
}

func (r *ProviderSessionRepository) CompleteRemoteRevocation(
	ctx context.Context,
	completion auth.ProviderRemoteRevocationCompletion,
) error {
	if r == nil || r.db == nil || strings.TrimSpace(completion.SessionID) == "" ||
		completion.RemoteRevision <= 0 {
		return auth.ErrProviderSessionInvalid
	}
	if err := completion.Outcome.Validate(); err != nil {
		return err
	}
	safeErrorCode := safeRemoteErrorCode(completion.SafeErrorCode)
	retryable := !completion.Terminal && completion.Outcome.Retryable
	if retryable && completion.NextAttemptAt.IsZero() {
		return auth.ErrProviderSessionInvalid
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return auth.ErrProviderSessionUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return auth.ErrProviderSessionUnavailable
	}
	var terminalAt any
	if !retryable {
		terminalAt = now
	}
	result, err := tx.NewUpdate().
		Model((*ProviderSessionModel)(nil)).
		Set("remote_revocation_status = ?", completion.Outcome.Status).
		Set("remote_revocation_retryable = ?", retryable).
		Set("residual_access_expires_at = ?", nullableTime(completion.Outcome.ResidualAccessExpires)).
		Set("remote_revocation_next_attempt_at = ?", nullableTime(completion.NextAttemptAt)).
		Set("remote_revocation_lease_owner = NULL").
		Set("remote_revocation_lease_until = NULL").
		Set("remote_revocation_safe_error_code = ?", safeErrorCode).
		Set("remote_revocation_terminal_at = ?", terminalAt).
		Set("remote_revocation_revision = remote_revocation_revision + 1").
		Set("updated_at = ?", now).
		Where("id = ? AND status = ? AND remote_revocation_revision = ? AND remote_revocation_lease_owner <> ''",
			completion.SessionID,
			auth.ProviderSessionRevoked,
			completion.RemoteRevision,
		).
		Exec(ctx)
	if err != nil {
		return auth.ErrProviderSessionUnavailable
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return auth.ErrProviderSessionConflict
	}
	if !retryable {
		if _, err := tx.NewDelete().
			Model((*ProviderSessionTokenModel)(nil)).
			Where("session_id = ?", completion.SessionID).
			Exec(ctx); err != nil {
			return auth.ErrProviderSessionUnavailable
		}
	}
	if err := tx.Commit(); err != nil {
		return auth.ErrProviderSessionUnavailable
	}
	return nil
}

var _ auth.ProviderRemoteRevocationRepository = (*ProviderSessionRepository)(nil)

//nolint:gocyclo // Retention, retry, and refresh-lease cleanup rules remain explicit.
func (r *ProviderSessionRepository) Cleanup(ctx context.Context, policy auth.ProviderSessionCleanupPolicy) (auth.ProviderSessionCleanupResult, error) {
	if r == nil || r.db == nil {
		return auth.ProviderSessionCleanupResult{}, auth.ErrProviderSessionUnavailable
	}
	if policy.BatchSize <= 0 {
		policy.BatchSize = 100
	}
	if policy.BatchSize > 10_000 {
		policy.BatchSize = 10_000
	}
	if policy.SessionRetention <= 0 {
		policy.SessionRetention = auth.DefaultProviderSessionRetention
	}
	if policy.TokenRetention <= 0 {
		policy.TokenRetention = auth.DefaultProviderTokenRetention
	}
	if policy.Now.IsZero() {
		var err error
		policy.Now, err = databaseTime(ctx, r.db)
		if err != nil {
			return auth.ProviderSessionCleanupResult{}, auth.ErrProviderSessionUnavailable
		}
	}
	now := policy.Now.UTC()
	var expiredRemoteWork []string
	if err := r.db.NewSelect().
		Model((*ProviderSessionModel)(nil)).
		Column("id").
		Where("remote_revocation_retryable = TRUE AND remote_revocation_work_expires_at IS NOT NULL AND remote_revocation_work_expires_at <= ?", now).
		Limit(policy.BatchSize).
		Scan(ctx, &expiredRemoteWork); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return auth.ProviderSessionCleanupResult{}, auth.ErrProviderSessionUnavailable
	}
	result := auth.ProviderSessionCleanupResult{}
	if len(expiredRemoteWork) > 0 {
		if _, err := r.db.NewUpdate().
			Model((*ProviderSessionModel)(nil)).
			Set("remote_revocation_retryable = FALSE").
			Set("remote_revocation_status = ?", auth.ProviderRemoteRevocationFailed).
			Set("remote_revocation_safe_error_code = ?", "retry_retention_expired").
			Set("remote_revocation_lease_owner = NULL").
			Set("remote_revocation_lease_until = NULL").
			Set("remote_revocation_terminal_at = ?", now).
			Set("updated_at = ?", now).
			Where("id IN (?) AND remote_revocation_retryable = TRUE", bun.In(expiredRemoteWork)).
			Exec(ctx); err != nil {
			return result, auth.ErrProviderSessionUnavailable
		}
		deleted, err := r.db.NewDelete().
			Model((*ProviderSessionTokenModel)(nil)).
			Where("session_id IN (?)", bun.In(expiredRemoteWork)).
			Exec(ctx)
		if err != nil {
			return result, auth.ErrProviderSessionUnavailable
		}
		count, _ := deleted.RowsAffected()
		result.TokenRecords += count
	}
	if _, err := r.db.NewUpdate().Model((*ProviderSessionModel)(nil)).
		Set("status = ?", auth.ProviderSessionExpired).
		Set("updated_at = ?", now).
		Where("status = ? AND (idle_expires_at <= ? OR max_expires_at <= ?)", auth.ProviderSessionAvailable, now, now).
		Exec(ctx); err != nil {
		return auth.ProviderSessionCleanupResult{}, auth.ErrProviderSessionUnavailable
	}

	var candidates []ProviderSessionModel
	if err := r.db.NewSelect().Model(&candidates).
		Where("status IN (?, ?, ?)", auth.ProviderSessionRevoked, auth.ProviderSessionExpired, auth.ProviderSessionUncertain).
		Order("updated_at ASC").
		Limit(policy.BatchSize).
		Scan(ctx); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return auth.ProviderSessionCleanupResult{}, auth.ErrProviderSessionUnavailable
	}
	tokenCutoff := now.Add(-policy.TokenRetention)
	sessionCutoff := now.Add(-policy.SessionRetention)
	for i := range candidates {
		model := &candidates[i]
		if !model.UpdatedAt.After(tokenCutoff) && !model.RemoteRevocationRetryable {
			deleted, err := r.db.NewDelete().Model((*ProviderSessionTokenModel)(nil)).
				Where("session_id = ? AND token_revision = ?", model.ID, model.TokenRevision).
				Exec(ctx)
			if err != nil {
				return result, auth.ErrProviderSessionUnavailable
			}
			count, _ := deleted.RowsAffected()
			result.TokenRecords += count
		}
		if !model.UpdatedAt.After(sessionCutoff) && !model.RemoteRevocationRetryable {
			deleted, err := r.db.NewDelete().Model((*ProviderSessionModel)(nil)).
				Where("id = ? AND token_revision = ? AND status IN (?, ?, ?)",
					model.ID, model.TokenRevision, auth.ProviderSessionRevoked, auth.ProviderSessionExpired, auth.ProviderSessionUncertain).
				Exec(ctx)
			if err != nil {
				return result, auth.ErrProviderSessionUnavailable
			}
			count, _ := deleted.RowsAffected()
			result.SessionRecords += count
		}
	}
	return result, nil
}

func (r *ProviderSessionRepository) sessionByID(ctx context.Context, id string) (auth.ProviderSession, error) {
	model, err := selectProviderSession(ctx, r.db, r.db.Dialect().Name(), "id = ?", id)
	if err != nil {
		return auth.ProviderSession{}, err
	}
	return sessionFromModel(model)
}

//nolint:gocyclo // Persisted session and encrypted-token invariants are validated together.
func providerSessionCreateModels(input auth.ProviderSessionCreate) (*ProviderSessionModel, *ProviderSessionTokenModel, error) {
	s := input.Session
	if strings.TrimSpace(s.ID) == "" || strings.TrimSpace(s.LocalSessionID) == "" ||
		len(input.LookupHash) != sha256Size || s.TokenRevision <= 0 ||
		!s.Status.Usable() || s.MaxExpiresAt.IsZero() || s.IdleExpiresAt.IsZero() ||
		s.IdleExpiresAt.After(s.MaxExpiresAt) {
		return nil, nil, auth.ErrProviderSessionInvalid
	}
	if err := s.Binding.Validate(); err != nil {
		return nil, nil, err
	}
	binding := normalizedBinding(s.Binding)
	applicationSubject := strings.TrimSpace(s.Principal.ApplicationSubject)
	providerSubject := strings.TrimSpace(s.Principal.ProviderSubject)
	principalProvider := strings.TrimSpace(s.Principal.Provider)
	principalClientID := strings.TrimSpace(s.Principal.ClientID)
	principalTenantID := strings.TrimSpace(s.Principal.TenantID)
	if applicationSubject == "" || providerSubject == "" {
		return nil, nil, auth.ErrProviderSessionInvalid
	}
	if principalProvider != binding.Provider || principalClientID != binding.ClientID ||
		(principalTenantID != "" && principalTenantID != binding.TenantID) {
		return nil, nil, auth.ErrProviderSessionBinding
	}
	principal, err := json.Marshal(s.Principal)
	if err != nil {
		return nil, nil, auth.ErrProviderSessionInvalid
	}
	session := &ProviderSessionModel{
		ID:                 s.ID,
		LocalSessionID:     s.LocalSessionID,
		LookupHash:         append([]byte(nil), input.LookupHash...),
		ApplicationSubject: applicationSubject,
		ProviderSubject:    providerSubject,
		ProviderSessionID:  s.Principal.ProviderSessionID,
		Host:               binding.Host,
		ApplicationID:      binding.ApplicationID,
		Environment:        binding.Environment,
		TenantID:           binding.TenantID,
		Provider:           binding.Provider,
		Issuer:             binding.Issuer,
		OAuthClientID:      binding.ClientID,
		Principal:          principal,
		Status:             string(s.Status),
		TokenRevision:      s.TokenRevision,
		CreatedAt:          s.CreatedAt,
		LastSeenAt:         s.LastSeenAt,
		IdleExpiresAt:      s.IdleExpiresAt.UTC(),
		MaxExpiresAt:       s.MaxExpiresAt.UTC(),
	}
	token := &ProviderSessionTokenModel{
		SessionID:         s.ID,
		TokenRevision:     s.TokenRevision,
		EnvelopeVersion:   input.Tokens.Version,
		EnvelopeAlgorithm: input.Tokens.Algorithm,
		KeyID:             input.Tokens.KeyID,
		Nonce:             append([]byte(nil), input.Tokens.Nonce...),
		Ciphertext:        append([]byte(nil), input.Tokens.Ciphertext...),
	}
	if token.EnvelopeVersion == 0 || strings.TrimSpace(token.EnvelopeAlgorithm) == "" ||
		strings.TrimSpace(token.KeyID) == "" || len(token.Nonce) == 0 || len(token.Ciphertext) == 0 {
		return nil, nil, auth.ErrProviderTokenEnvelope
	}
	return session, token, nil
}

func lockProviderSessionAuthorizationFence(
	ctx context.Context,
	tx bun.Tx,
	dialectName dialect.Name,
	applicationSubject string,
	tenantID string,
	permissionVersion string,
	permissionVersionObservedAt time.Time,
) error {
	fence := &ProviderSessionAuthorizationFenceModel{
		ApplicationSubject:        strings.TrimSpace(applicationSubject),
		TenantID:                  strings.TrimSpace(tenantID),
		RequiredPermissionVersion: strings.TrimSpace(permissionVersion),
	}
	permissionVersionObservedAt = permissionVersionObservedAt.UTC()
	if fence.RequiredPermissionVersion != "" && !permissionVersionObservedAt.IsZero() {
		fence.PermissionVersionObservedAt = &permissionVersionObservedAt
	}
	if fence.ApplicationSubject == "" {
		return auth.ErrProviderSessionInvalid
	}
	tenantIDs := []string{""}
	if fence.TenantID != "" {
		tenantIDs = append(tenantIDs, fence.TenantID)
	}
	for _, tenantID := range tenantIDs {
		candidate := *fence
		candidate.TenantID = tenantID
		if _, err := tx.NewInsert().
			Model(&candidate).
			On("CONFLICT (application_subject, tenant_id) DO NOTHING").
			Exec(ctx); err != nil {
			return fmt.Errorf("%w: initialize authorization fence", auth.ErrProviderSessionUnavailable)
		}
	}

	var current []ProviderSessionAuthorizationFenceModel
	query := tx.NewSelect().
		Model(&current).
		Where("application_subject = ? AND tenant_id IN (?)", fence.ApplicationSubject, bun.In(tenantIDs)).
		Order("tenant_id ASC")
	if dialectName == dialect.PG {
		query = query.For("UPDATE")
	}
	if err := query.Scan(ctx); err != nil {
		return fmt.Errorf("%w: load authorization fence", auth.ErrProviderSessionUnavailable)
	}
	if len(current) != len(tenantIDs) {
		return fmt.Errorf("%w: incomplete authorization fence", auth.ErrProviderSessionUnavailable)
	}
	requiredVersion, err := newestRequiredPermissionVersion(current)
	if err != nil {
		return err
	}
	if requiredVersion != "" && requiredVersion != fence.RequiredPermissionVersion {
		return fmt.Errorf(
			"%w: principal permission version does not satisfy the current authorization fence",
			auth.ErrProviderSessionConflict,
		)
	}
	return nil
}

func newestRequiredPermissionVersion(
	fences []ProviderSessionAuthorizationFenceModel,
) (string, error) {
	var selected *ProviderSessionAuthorizationFenceModel
	for index := range fences {
		candidate := &fences[index]
		if candidate.RequiredPermissionVersion == "" {
			continue
		}
		if selected == nil {
			selected = candidate
			continue
		}
		switch {
		case selected.PermissionVersionObservedAt == nil &&
			candidate.PermissionVersionObservedAt != nil:
			selected = candidate
		case selected.PermissionVersionObservedAt != nil &&
			candidate.PermissionVersionObservedAt != nil &&
			candidate.PermissionVersionObservedAt.After(*selected.PermissionVersionObservedAt):
			selected = candidate
		case selected.PermissionVersionObservedAt == nil &&
			candidate.PermissionVersionObservedAt == nil &&
			candidate.RequiredPermissionVersion != selected.RequiredPermissionVersion:
			return "", fmt.Errorf(
				"%w: authorization fences have ambiguous versions",
				auth.ErrProviderSessionConflict,
			)
		case selected.PermissionVersionObservedAt != nil &&
			candidate.PermissionVersionObservedAt != nil &&
			candidate.PermissionVersionObservedAt.Equal(*selected.PermissionVersionObservedAt) &&
			candidate.RequiredPermissionVersion != selected.RequiredPermissionVersion:
			return "", fmt.Errorf(
				"%w: authorization fences have conflicting versions",
				auth.ErrProviderSessionConflict,
			)
		}
	}
	if selected == nil {
		return "", nil
	}
	return selected.RequiredPermissionVersion, nil
}

func advanceProviderSessionAuthorizationFence(
	ctx context.Context,
	tx bun.Tx,
	applicationSubject string,
	tenantID string,
	permissionVersion string,
	permissionVersionObservedAt time.Time,
	dialectName dialect.Name,
) error {
	permissionVersionObservedAt = permissionVersionObservedAt.UTC()
	fence := &ProviderSessionAuthorizationFenceModel{
		ApplicationSubject:          strings.TrimSpace(applicationSubject),
		TenantID:                    strings.TrimSpace(tenantID),
		RequiredPermissionVersion:   strings.TrimSpace(permissionVersion),
		PermissionVersionObservedAt: &permissionVersionObservedAt,
	}
	if fence.ApplicationSubject == "" || fence.RequiredPermissionVersion == "" ||
		permissionVersionObservedAt.IsZero() {
		return auth.ErrProviderSessionInvalid
	}
	if _, err := tx.NewInsert().
		Model(fence).
		On("CONFLICT (application_subject, tenant_id) DO NOTHING").
		Exec(ctx); err != nil {
		return fmt.Errorf("%w: initialize authorization fence", auth.ErrProviderSessionUnavailable)
	}

	current := &ProviderSessionAuthorizationFenceModel{}
	query := tx.NewSelect().
		Model(current).
		Where("application_subject = ? AND tenant_id = ?", fence.ApplicationSubject, fence.TenantID).
		Limit(1)
	if dialectName == dialect.PG {
		query = query.For("UPDATE")
	}
	if err := query.Scan(ctx); err != nil {
		return fmt.Errorf("%w: load authorization fence", auth.ErrProviderSessionUnavailable)
	}
	if current.PermissionVersionObservedAt != nil &&
		!permissionVersionObservedAt.After(current.PermissionVersionObservedAt.UTC()) {
		// Duplicate and out-of-order deliveries still revoke existing sessions,
		// but cannot roll the creation fence back to an older version.
		return nil
	}
	if _, err := tx.NewUpdate().
		Model((*ProviderSessionAuthorizationFenceModel)(nil)).
		Set("required_permission_version = ?", fence.RequiredPermissionVersion).
		Set("permission_version_observed_at = ?", permissionVersionObservedAt).
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("application_subject = ? AND tenant_id = ?", fence.ApplicationSubject, fence.TenantID).
		Exec(ctx); err != nil {
		return fmt.Errorf("%w: advance authorization fence", auth.ErrProviderSessionUnavailable)
	}
	return nil
}

func selectProviderSession(ctx context.Context, db bun.IDB, dialectName dialect.Name, where string, args ...any) (*ProviderSessionModel, error) {
	var model ProviderSessionModel
	query := db.NewSelect().Model(&model).Where(where, args...).Limit(1)
	if dialectName == dialect.PG {
		query = query.For("UPDATE")
	}
	if err := query.Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, auth.ErrProviderSessionNotFound
		}
		return nil, auth.ErrProviderSessionUnavailable
	}
	return &model, nil
}

func selectProviderSessionTokens(ctx context.Context, db bun.IDB, sessionID string) (*ProviderSessionTokenModel, error) {
	var model ProviderSessionTokenModel
	if err := db.NewSelect().Model(&model).Where("session_id = ?", sessionID).Limit(1).Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, auth.ErrProviderSessionUnavailable
		}
		return nil, auth.ErrProviderSessionUnavailable
	}
	return &model, nil
}

func sessionFromModel(model *ProviderSessionModel) (auth.ProviderSession, error) {
	if model == nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionNotFound
	}
	var principal auth.PrincipalSnapshot
	if err := json.Unmarshal(model.Principal, &principal); err != nil {
		return auth.ProviderSession{}, auth.ErrProviderSessionInvalid
	}
	session := auth.ProviderSession{
		ID:             model.ID,
		LocalSessionID: model.LocalSessionID,
		Principal:      principal,
		Binding: auth.ProviderSessionBinding{
			Host: model.Host, ApplicationID: model.ApplicationID, Environment: model.Environment,
			TenantID: model.TenantID, Provider: model.Provider, Issuer: model.Issuer, ClientID: model.OAuthClientID,
		},
		Status:           auth.ProviderSessionStatus(model.Status),
		TokenRevision:    model.TokenRevision,
		CreatedAt:        model.CreatedAt.UTC(),
		LastSeenAt:       model.LastSeenAt.UTC(),
		IdleExpiresAt:    model.IdleExpiresAt.UTC(),
		MaxExpiresAt:     model.MaxExpiresAt.UTC(),
		RevocationReason: model.RevocationReason,
		RemoteRevocation: auth.ProviderRemoteRevocationOutcome{
			Status:    auth.ProviderRemoteRevocationStatus(model.RemoteRevocationStatus),
			Retryable: model.RemoteRevocationRetryable,
		},
	}
	if model.RefreshAttemptID != nil {
		session.RefreshAttemptID = *model.RefreshAttemptID
	}
	if model.RefreshBaseRevision != nil {
		session.RefreshBaseRevision = *model.RefreshBaseRevision
	}
	if model.RefreshLeaseUntil != nil {
		session.RefreshLeaseUntil = model.RefreshLeaseUntil.UTC()
	}
	if model.RevokedAt != nil {
		session.RevokedAt = model.RevokedAt.UTC()
	}
	if model.ResidualAccessExpiresAt != nil {
		session.RemoteRevocation.ResidualAccessExpires = model.ResidualAccessExpiresAt.UTC()
	}
	session.RemoteAttemptCount = model.RemoteRevocationAttemptCount
	session.RemoteLeaseOwner = model.RemoteRevocationLeaseOwner
	session.RemoteRevision = model.RemoteRevocationRevision
	session.RemoteSafeErrorCode = model.RemoteRevocationSafeErrorCode
	if model.RemoteRevocationNextAttemptAt != nil {
		session.RemoteNextAttemptAt = model.RemoteRevocationNextAttemptAt.UTC()
	}
	if model.RemoteRevocationLeaseUntil != nil {
		session.RemoteLeaseUntil = model.RemoteRevocationLeaseUntil.UTC()
	}
	if model.RemoteRevocationWorkExpiresAt != nil {
		session.RemoteWorkExpiresAt = model.RemoteRevocationWorkExpiresAt.UTC()
	}
	if model.RemoteRevocationTerminalAt != nil {
		session.RemoteTerminalAt = model.RemoteRevocationTerminalAt.UTC()
	}
	return session, nil
}

func tokenEnvelopeFromModel(model *ProviderSessionTokenModel) auth.TokenEnvelope {
	return auth.TokenEnvelope{
		Version: model.EnvelopeVersion, Algorithm: model.EnvelopeAlgorithm, KeyID: model.KeyID,
		Nonce: append([]byte(nil), model.Nonce...), Ciphertext: append([]byte(nil), model.Ciphertext...),
	}
}

func statusError(status auth.ProviderSessionStatus) error {
	switch status {
	case auth.ProviderSessionRevoked:
		return auth.ErrProviderSessionRevoked
	case auth.ProviderSessionExpired:
		return auth.ErrProviderSessionExpired
	case auth.ProviderSessionUncertain:
		return auth.ErrProviderSessionUncertain
	case auth.ProviderSessionRefreshing:
		return auth.ErrProviderRefreshInProgress
	default:
		return auth.ErrProviderSessionInvalid
	}
}

func normalizedBinding(binding auth.ProviderSessionBinding) auth.ProviderSessionBinding {
	return auth.ProviderSessionBinding{
		Host:          strings.ToLower(strings.TrimSpace(binding.Host)),
		ApplicationID: strings.TrimSpace(binding.ApplicationID),
		Environment:   strings.TrimSpace(binding.Environment),
		TenantID:      strings.TrimSpace(binding.TenantID),
		Provider:      strings.TrimSpace(binding.Provider),
		Issuer:        strings.TrimRight(strings.TrimSpace(binding.Issuer), "/"),
		ClientID:      strings.TrimSpace(binding.ClientID),
	}
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func providerSessionReasonStorage(value string) (string, string) {
	reason := auth.ParseProviderSessionReason(value)
	return string(reason.Code), string(auth.EnsureProviderAuditFingerprint(
		string(reason.DetailFingerprint),
	))
}

func safeRemoteErrorCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "" {
		return ""
	}
	if len(code) > 64 {
		return "remote_error"
	}
	for _, char := range code {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' {
			return "remote_error"
		}
	}
	return code
}

const sha256Size = 32

var _ auth.ProviderSessionRepository = (*ProviderSessionRepository)(nil)
