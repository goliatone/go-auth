package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/goliatone/go-auth"
	bunrepo "github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type IdentifierModel struct {
	bun.BaseModel `bun:"table:user_identifiers"`

	ID         uuid.UUID      `bun:"id,pk,nullzero,type:uuid"`
	UserID     uuid.UUID      `bun:"user_id,notnull,type:uuid"`
	Provider   string         `bun:"provider,notnull"`
	Identifier string         `bun:"identifier,notnull"`
	Metadata   map[string]any `bun:"metadata,type:jsonb"`
	CreatedAt  time.Time      `bun:"created_at,default:current_timestamp"`
	UpdatedAt  time.Time      `bun:"updated_at,default:current_timestamp"`
}

type IdentifierStore struct {
	db *bun.DB
}

func NewIdentifierStore(db *bun.DB) *IdentifierStore {
	return &IdentifierStore{db: db}
}

func (s *IdentifierStore) FindUserID(ctx context.Context, provider, identifier string) (string, error) {
	provider = strings.TrimSpace(provider)
	identifier = strings.TrimSpace(identifier)
	if provider == "" || identifier == "" {
		return "", bunrepo.NewRecordNotFound()
	}

	var model IdentifierModel
	err := s.db.NewSelect().
		Model(&model).
		Where("provider = ? AND identifier = ?", provider, identifier).
		Limit(1).
		Scan(ctx)
	if err != nil {
		if bunrepo.IsRecordNotFound(err) || err == sql.ErrNoRows {
			return "", bunrepo.NewRecordNotFound().WithMetadata(map[string]any{
				"provider":   provider,
				"identifier": identifier,
			})
		}
		return "", err
	}

	return model.UserID.String(), nil
}

func (s *IdentifierStore) Upsert(ctx context.Context, userID, provider, identifier string) error {
	provider = strings.TrimSpace(provider)
	identifier = strings.TrimSpace(identifier)
	if provider == "" || identifier == "" {
		return fmt.Errorf("identifier store: provider and identifier are required")
	}

	parsedID, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return fmt.Errorf("identifier store: invalid user ID: %w", err)
	}

	model := &IdentifierModel{
		ID:         uuid.New(),
		UserID:     parsedID,
		Provider:   provider,
		Identifier: identifier,
		Metadata:   map[string]any{},
		UpdatedAt:  time.Now(),
	}

	_, err = s.db.NewInsert().
		Model(model).
		On("CONFLICT (provider, identifier) DO UPDATE").
		Set("user_id = EXCLUDED.user_id").
		Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)
	return err
}

var _ auth.IdentifierStore = (*IdentifierStore)(nil)
