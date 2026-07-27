package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
)

type OIDCStateModel struct {
	bun.BaseModel `bun:"table:oidc_states"`

	StateHash          []byte    `bun:"state_hash,pk"`
	ProviderKey        string    `bun:"provider_key,notnull"`
	Nonce              string    `bun:"nonce,notnull"`
	VerifierVersion    uint8     `bun:"verifier_version,notnull"`
	VerifierAlgorithm  string    `bun:"verifier_algorithm,notnull"`
	VerifierKeyID      string    `bun:"verifier_key_id,notnull"`
	VerifierNonce      []byte    `bun:"verifier_nonce,notnull"`
	VerifierCiphertext []byte    `bun:"verifier_ciphertext,notnull"`
	RedirectTo         string    `bun:"redirect_to,notnull"`
	CreatedAt          time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp"`
	ExpiresAt          time.Time `bun:"expires_at,notnull"`
}

// OIDCStateStore preserves oidc.StateStore compatibility while providing
// durable, single-use, encrypted PKCE state.
type OIDCStateStore struct {
	db     *bun.DB
	cipher auth.TokenCipher
}

func NewOIDCStateStore(db *bun.DB, cipher auth.TokenCipher) (*OIDCStateStore, error) {
	if db == nil || cipher == nil {
		return nil, fmt.Errorf("%w: durable state database and cipher are required", oidc.ErrInvalidConfig)
	}
	return &OIDCStateStore{db: db, cipher: cipher}, nil
}

func (s *OIDCStateStore) Save(ctx context.Context, record oidc.StateRecord) error {
	if s == nil || s.db == nil || s.cipher == nil {
		return oidc.ErrInvalidState
	}
	if strings.TrimSpace(record.State) == "" ||
		strings.TrimSpace(record.ProviderKey) == "" ||
		strings.TrimSpace(record.Nonce) == "" ||
		strings.TrimSpace(record.CodeVerifier) == "" ||
		record.ExpiresAt.IsZero() {
		return oidc.ErrInvalidState
	}

	stateHash := hashOIDCState(record.State)
	envelope, err := s.cipher.Seal(ctx, []byte(record.CodeVerifier), oidcStateAssociatedData(stateHash, record.ProviderKey, record.ExpiresAt))
	if err != nil {
		return fmt.Errorf("%w: protect PKCE verifier", oidc.ErrInvalidState)
	}
	model := &OIDCStateModel{
		StateHash:          stateHash,
		ProviderKey:        strings.TrimSpace(record.ProviderKey),
		Nonce:              record.Nonce,
		VerifierVersion:    envelope.Version,
		VerifierAlgorithm:  envelope.Algorithm,
		VerifierKeyID:      envelope.KeyID,
		VerifierNonce:      append([]byte(nil), envelope.Nonce...),
		VerifierCiphertext: append([]byte(nil), envelope.Ciphertext...),
		RedirectTo:         record.RedirectTo,
		ExpiresAt:          record.ExpiresAt.UTC(),
	}
	if !record.CreatedAt.IsZero() {
		model.CreatedAt = record.CreatedAt.UTC()
	}
	if _, err := s.db.NewInsert().Model(model).Exec(ctx); err != nil {
		return fmt.Errorf("%w: persist durable state", oidc.ErrInvalidState)
	}
	return nil
}

func (s *OIDCStateStore) Consume(ctx context.Context, rawState string) (oidc.StateRecord, error) {
	if s == nil || s.db == nil || s.cipher == nil || strings.TrimSpace(rawState) == "" {
		return oidc.StateRecord{}, oidc.ErrInvalidState
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return oidc.StateRecord{}, fmt.Errorf("%w: durable state unavailable", oidc.ErrInvalidState)
	}
	defer func() { _ = tx.Rollback() }()

	stateHash := hashOIDCState(rawState)
	var model OIDCStateModel
	query := tx.NewSelect().Model(&model).Where("state_hash = ?", stateHash).Limit(1)
	if s.db.Dialect().Name() == dialect.PG {
		query = query.For("UPDATE")
	}
	if scanErr := query.Scan(ctx); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return oidc.StateRecord{}, oidc.ErrInvalidState
		}
		return oidc.StateRecord{}, fmt.Errorf("%w: durable state unavailable", oidc.ErrInvalidState)
	}

	dbNow, err := databaseTime(ctx, tx)
	if err != nil {
		return oidc.StateRecord{}, fmt.Errorf("%w: database time unavailable", oidc.ErrInvalidState)
	}
	if _, deleteErr := tx.NewDelete().Model((*OIDCStateModel)(nil)).Where("state_hash = ?", stateHash).Exec(ctx); deleteErr != nil {
		return oidc.StateRecord{}, fmt.Errorf("%w: consume durable state", oidc.ErrInvalidState)
	}
	if commitErr := tx.Commit(); commitErr != nil {
		return oidc.StateRecord{}, fmt.Errorf("%w: consume durable state", oidc.ErrInvalidState)
	}

	if !dbNow.Before(model.ExpiresAt) {
		return oidc.StateRecord{}, oidc.ErrInvalidState
	}
	envelope := auth.TokenEnvelope{
		Version:    model.VerifierVersion,
		Algorithm:  model.VerifierAlgorithm,
		KeyID:      model.VerifierKeyID,
		Nonce:      append([]byte(nil), model.VerifierNonce...),
		Ciphertext: append([]byte(nil), model.VerifierCiphertext...),
	}
	verifier, err := s.cipher.Open(ctx, envelope, oidcStateAssociatedData(stateHash, model.ProviderKey, model.ExpiresAt))
	if err != nil {
		return oidc.StateRecord{}, fmt.Errorf("%w: PKCE verifier unavailable", oidc.ErrInvalidState)
	}
	return oidc.StateRecord{
		State:        rawState,
		Nonce:        model.Nonce,
		CodeVerifier: string(verifier),
		ProviderKey:  model.ProviderKey,
		RedirectTo:   model.RedirectTo,
		CreatedAt:    model.CreatedAt,
		ExpiresAt:    model.ExpiresAt,
	}, nil
}

func (s *OIDCStateStore) CleanupExpired(ctx context.Context, before time.Time, limit int) (int64, error) {
	if s == nil || s.db == nil {
		return 0, oidc.ErrInvalidState
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 10_000 {
		limit = 10_000
	}
	if before.IsZero() {
		var err error
		before, err = databaseTime(ctx, s.db)
		if err != nil {
			return 0, err
		}
	}

	var models []OIDCStateModel
	if err := s.db.NewSelect().
		Model(&models).
		Column("state_hash").
		Where("expires_at <= ?", before.UTC()).
		Order("expires_at ASC").
		Limit(limit).
		Scan(ctx); err != nil {
		return 0, err
	}
	var removed int64
	for i := range models {
		result, err := s.db.NewDelete().
			Model((*OIDCStateModel)(nil)).
			Where("state_hash = ? AND expires_at <= ?", models[i].StateHash, before.UTC()).
			Exec(ctx)
		if err != nil {
			return removed, err
		}
		count, _ := result.RowsAffected()
		removed += count
	}
	return removed, nil
}

func hashOIDCState(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return append([]byte(nil), sum[:]...)
}

func oidcStateAssociatedData(hash []byte, provider string, expiresAt time.Time) []byte {
	return []byte(strings.Join([]string{
		"oidc-state-v1",
		base64.RawURLEncoding.EncodeToString(hash),
		strings.TrimSpace(provider),
		expiresAt.UTC().Format(time.RFC3339Nano),
	}, "\x00"))
}

func databaseTime(ctx context.Context, db bun.IDB) (time.Time, error) {
	var now time.Time
	if err := db.NewRaw("SELECT CURRENT_TIMESTAMP").Scan(ctx, &now); err != nil {
		return time.Time{}, err
	}
	return now.UTC(), nil
}

var (
	_ oidc.StateStore            = (*OIDCStateStore)(nil)
	_ auth.StateStoreMaintenance = (*OIDCStateStore)(nil)
)
