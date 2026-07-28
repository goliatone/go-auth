package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
)

type LifecycleOperationModel struct {
	bun.BaseModel `bun:"table:lifecycle_operations"`

	OperationID                   string     `bun:"operation_id,pk"`
	Fingerprint                   string     `bun:"fingerprint,notnull"`
	Action                        string     `bun:"action,notnull"`
	LocalPhase                    string     `bun:"local_phase,notnull"`
	RemotePhase                   string     `bun:"remote_phase,notnull"`
	FreshnessPhase                string     `bun:"freshness_phase,notnull"`
	LocalStatus                   string     `bun:"local_status"`
	LocalSessionEffect            string     `bun:"local_session_effect"`
	RemoteStatus                  string     `bun:"remote_status"`
	RemoteRetryable               bool       `bun:"remote_retryable,notnull"`
	RemoteRequestFingerprint      string     `bun:"remote_request_fingerprint"`
	RemoteSessionEffect           string     `bun:"remote_session_effect"`
	RemoteResidualAccessExpiresAt *time.Time `bun:"remote_residual_access_expires_at"`
	FreshnessStatus               string     `bun:"freshness_status"`
	ProviderIdempotencyKey        string     `bun:"provider_idempotency_key,notnull"`
	RemoteAttempt                 int        `bun:"remote_attempt,notnull"`
	RemoteLeaseOwner              string     `bun:"remote_lease_owner"`
	RemoteLeaseUntil              *time.Time `bun:"remote_lease_until"`
	Revision                      int64      `bun:"revision,notnull"`
	Completed                     bool       `bun:"completed,notnull"`
	CreatedAt                     time.Time  `bun:"created_at,nullzero,notnull,default:current_timestamp"`
	UpdatedAt                     time.Time  `bun:"updated_at,nullzero,notnull,default:current_timestamp"`
}

type LifecycleOperationRepository struct {
	db *bun.DB
}

func NewLifecycleOperationRepository(db *bun.DB) (*LifecycleOperationRepository, error) {
	if db == nil {
		return nil, auth.ErrLifecycleOperationUnavailable
	}
	return &LifecycleOperationRepository{db: db}, nil
}

func (r *LifecycleOperationRepository) Durable() bool {
	return r != nil && r.db != nil && r.db.Dialect().Name() == dialect.PG
}

func (r *LifecycleOperationRepository) Claim(
	ctx context.Context,
	claim auth.LifecycleOperationClaim,
) (auth.LifecycleOperationRecord, auth.LifecycleOperationClaimDisposition, error) {
	if r == nil || r.db == nil || strings.TrimSpace(claim.OperationID) == "" ||
		strings.TrimSpace(claim.Fingerprint) == "" {
		return auth.LifecycleOperationRecord{}, "", auth.ErrProviderOperationInvalid
	}
	now, err := databaseTime(ctx, r.db)
	if err != nil {
		return auth.LifecycleOperationRecord{}, "", auth.ErrLifecycleOperationUnavailable
	}
	model := &LifecycleOperationModel{
		OperationID:            strings.TrimSpace(claim.OperationID),
		Fingerprint:            strings.TrimSpace(claim.Fingerprint),
		Action:                 string(claim.Action),
		LocalPhase:             string(auth.LifecyclePhasePending),
		RemotePhase:            string(auth.LifecyclePhasePending),
		FreshnessPhase:         string(auth.LifecyclePhasePending),
		ProviderIdempotencyKey: strings.TrimSpace(claim.Fingerprint),
		Revision:               1,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	result, err := r.db.NewInsert().
		Model(model).
		On("CONFLICT (operation_id) DO NOTHING").
		Exec(ctx)
	if err != nil {
		return auth.LifecycleOperationRecord{}, "", auth.ErrLifecycleOperationUnavailable
	}
	affected, _ := result.RowsAffected()
	current, err := r.loadModel(ctx, model.OperationID)
	if err != nil {
		return auth.LifecycleOperationRecord{}, "", err
	}
	if current.Fingerprint != model.Fingerprint {
		return auth.LifecycleOperationRecord{}, "", fmt.Errorf(
			"%w: operation ID reuse mismatch",
			auth.ErrProviderOperationConflict,
		)
	}
	disposition := auth.LifecycleOperationExisting
	if affected == 1 {
		disposition = auth.LifecycleOperationClaimed
	}
	return lifecycleOperationFromModel(current), disposition, nil
}

func (r *LifecycleOperationRepository) Load(
	ctx context.Context,
	operationID string,
) (auth.LifecycleOperationRecord, error) {
	model, err := r.loadModel(ctx, strings.TrimSpace(operationID))
	if err != nil {
		return auth.LifecycleOperationRecord{}, err
	}
	return lifecycleOperationFromModel(model), nil
}

func (r *LifecycleOperationRepository) Advance(
	ctx context.Context,
	expectedRevision int64,
	next auth.LifecycleOperationRecord,
) (auth.LifecycleOperationRecord, error) {
	if r == nil || r.db == nil || expectedRevision <= 0 {
		return auth.LifecycleOperationRecord{}, auth.ErrLifecycleOperationUnavailable
	}
	if err := next.Validate(); err != nil {
		return auth.LifecycleOperationRecord{}, err
	}
	now, err := databaseTime(ctx, r.db)
	if err != nil {
		return auth.LifecycleOperationRecord{}, auth.ErrLifecycleOperationUnavailable
	}
	nextRevision := expectedRevision + 1
	result, err := r.db.NewUpdate().
		Model((*LifecycleOperationModel)(nil)).
		Set("local_phase = ?", next.LocalPhase).
		Set("remote_phase = ?", next.RemotePhase).
		Set("freshness_phase = ?", next.FreshnessPhase).
		Set("local_status = ?", next.Local.Status).
		Set("local_session_effect = ?", next.Local.ProviderSessionEffect).
		Set("remote_status = ?", next.Remote.Status).
		Set("remote_retryable = ?", next.Remote.Retryable).
		Set("remote_request_fingerprint = ?", auth.FingerprintProviderAuditValue(next.Remote.ProviderRequestID)).
		Set("remote_session_effect = ?", next.Remote.ProviderSessionEffect).
		Set("remote_residual_access_expires_at = ?", nullableTime(next.Remote.ResidualAccessExpires)).
		Set("freshness_status = ?", next.Freshness.Status).
		Set("provider_idempotency_key = ?", next.ProviderIdempotencyKey).
		Set("remote_attempt = ?", next.RemoteAttempt).
		Set("remote_lease_owner = ?", next.RemoteLeaseOwner).
		Set("remote_lease_until = ?", nullableTime(next.RemoteLeaseUntil)).
		Set("revision = ?", nextRevision).
		Set("completed = ?", next.Completed).
		Set("updated_at = ?", now).
		Where("operation_id = ? AND fingerprint = ? AND revision = ?",
			next.OperationID,
			next.Fingerprint,
			expectedRevision,
		).
		Exec(ctx)
	if err != nil {
		return auth.LifecycleOperationRecord{}, auth.ErrLifecycleOperationUnavailable
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return auth.LifecycleOperationRecord{}, auth.ErrLifecycleOperationConflict
	}
	next.Revision = nextRevision
	next.UpdatedAt = now
	return next, nil
}

//nolint:gocyclo // Durable claim selection and lease advancement remain explicit and transactional.
func (r *LifecycleOperationRepository) ClaimPending(
	ctx context.Context,
	policy auth.LifecycleOperationPendingPolicy,
) ([]auth.LifecycleOperationRecord, error) {
	if r == nil || r.db == nil {
		return nil, auth.ErrLifecycleOperationUnavailable
	}
	if policy.Now.IsZero() {
		var err error
		policy.Now, err = databaseTime(ctx, r.db)
		if err != nil {
			return nil, auth.ErrLifecycleOperationUnavailable
		}
	}
	if policy.Lease <= 0 {
		policy.Lease = 30 * time.Second
	}
	if policy.Limit <= 0 {
		policy.Limit = 100
	}
	policy.LeaseOwner = strings.TrimSpace(policy.LeaseOwner)
	if policy.LeaseOwner == "" || policy.Lease < 5*time.Second || policy.Lease > 5*time.Minute ||
		policy.Limit > 10_000 {
		return nil, auth.ErrProviderOperationInvalid
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, auth.ErrLifecycleOperationUnavailable
	}
	defer func() { _ = tx.Rollback() }()

	var models []LifecycleOperationModel
	query := tx.NewSelect().
		Model(&models).
		Where(
			"(remote_phase = ? AND (remote_lease_until IS NULL OR remote_lease_until <= ?)) OR "+
				"(remote_phase = ? AND remote_lease_until IS NOT NULL AND remote_lease_until <= ?)",
			auth.LifecyclePhasePendingReconcile,
			policy.Now.UTC(),
			auth.LifecyclePhaseInFlight,
			policy.Now.UTC(),
		).
		Order("updated_at ASC").
		Limit(policy.Limit)
	if r.db.Dialect().Name() == dialect.PG {
		query = query.For("UPDATE SKIP LOCKED")
	}
	if err := query.Scan(ctx); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, auth.ErrLifecycleOperationUnavailable
	}
	out := make([]auth.LifecycleOperationRecord, 0, len(models))
	for index := range models {
		model := &models[index]
		leaseUntil := policy.Now.UTC().Add(policy.Lease)
		result, updateErr := tx.NewUpdate().
			Model((*LifecycleOperationModel)(nil)).
			Set("remote_phase = ?", auth.LifecyclePhasePendingReconcile).
			Set("remote_lease_owner = ?", policy.LeaseOwner).
			Set("remote_lease_until = ?", leaseUntil).
			Set("revision = revision + 1").
			Set("updated_at = ?", policy.Now.UTC()).
			Where("operation_id = ? AND revision = ?", model.OperationID, model.Revision).
			Exec(ctx)
		if updateErr != nil {
			return nil, auth.ErrLifecycleOperationUnavailable
		}
		affected, _ := result.RowsAffected()
		if affected != 1 {
			continue
		}
		model.RemotePhase = string(auth.LifecyclePhasePendingReconcile)
		model.RemoteLeaseOwner = policy.LeaseOwner
		model.RemoteLeaseUntil = &leaseUntil
		model.Revision++
		model.UpdatedAt = policy.Now.UTC()
		out = append(out, lifecycleOperationFromModel(model))
	}
	if err := tx.Commit(); err != nil {
		return nil, auth.ErrLifecycleOperationUnavailable
	}
	return out, nil
}

func (r *LifecycleOperationRepository) loadModel(
	ctx context.Context,
	operationID string,
) (*LifecycleOperationModel, error) {
	if operationID == "" {
		return nil, auth.ErrLifecycleOperationUnavailable
	}
	model := &LifecycleOperationModel{}
	if err := r.db.NewSelect().
		Model(model).
		Where("operation_id = ?", operationID).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, auth.ErrLifecycleOperationUnavailable
	}
	return model, nil
}

func lifecycleOperationFromModel(model *LifecycleOperationModel) auth.LifecycleOperationRecord {
	record := auth.LifecycleOperationRecord{
		OperationID:            model.OperationID,
		Fingerprint:            model.Fingerprint,
		Action:                 auth.ProviderOperationAction(model.Action),
		LocalPhase:             auth.LifecycleOperationPhase(model.LocalPhase),
		RemotePhase:            auth.LifecycleOperationPhase(model.RemotePhase),
		FreshnessPhase:         auth.LifecycleOperationPhase(model.FreshnessPhase),
		ProviderIdempotencyKey: model.ProviderIdempotencyKey,
		RemoteAttempt:          model.RemoteAttempt,
		RemoteLeaseOwner:       model.RemoteLeaseOwner,
		Revision:               model.Revision,
		Completed:              model.Completed,
		CreatedAt:              model.CreatedAt.UTC(),
		UpdatedAt:              model.UpdatedAt.UTC(),
		Local: auth.ProviderOperationOutcome{
			Status:                auth.ProviderOperationStatus(model.LocalStatus),
			ProviderSessionEffect: auth.ProviderSessionEffect(model.LocalSessionEffect),
		},
		Remote: auth.ProviderOperationOutcome{
			Status:                auth.ProviderOperationStatus(model.RemoteStatus),
			Retryable:             model.RemoteRetryable,
			ProviderRequestID:     model.RemoteRequestFingerprint,
			ProviderSessionEffect: auth.ProviderSessionEffect(model.RemoteSessionEffect),
		},
		Freshness: auth.ProviderOperationOutcome{
			Status: auth.ProviderOperationStatus(model.FreshnessStatus),
		},
	}
	if model.RemoteResidualAccessExpiresAt != nil {
		record.Remote.ResidualAccessExpires = model.RemoteResidualAccessExpiresAt.UTC()
	}
	if model.RemoteLeaseUntil != nil {
		record.RemoteLeaseUntil = model.RemoteLeaseUntil.UTC()
	}
	return record
}

var _ auth.LifecycleOperationStore = (*LifecycleOperationRepository)(nil)
