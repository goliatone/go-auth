package repository

import (
	"context"
	"database/sql"
	"errors"
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
	return s.findUserIDTx(ctx, s.db, provider, identifier)
}

func (s *IdentifierStore) findUserIDTx(ctx context.Context, db bun.IDB, provider, identifier string) (string, error) {
	provider = strings.TrimSpace(provider)
	identifier = strings.TrimSpace(identifier)
	if provider == "" || identifier == "" {
		return "", bunrepo.NewRecordNotFound()
	}

	var model IdentifierModel
	err := db.NewSelect().
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
	return s.Bind(ctx, userID, provider, identifier)
}

func (s *IdentifierStore) Bind(ctx context.Context, userID, provider, identifier string) error {
	return s.BindTx(ctx, s.db, userID, provider, identifier)
}

func (s *IdentifierStore) BindTx(ctx context.Context, db bun.IDB, userID, provider, identifier string) error {
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

	result, err := db.NewInsert().
		Model(model).
		On("CONFLICT (provider, identifier) DO NOTHING").
		Exec(ctx)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows > 0 {
		return nil
	}

	existingUserID, err := s.findUserIDTx(ctx, db, provider, identifier)
	if err != nil {
		return err
	}
	if existingUserID == parsedID.String() {
		return nil
	}
	conflict := auth.ErrIdentifierConflict.Clone()
	if conflict == nil {
		return auth.ErrIdentifierConflict
	}
	return conflict.WithMetadata(map[string]any{"provider": provider})
}

func (s *IdentifierStore) CreateUserAndBind(ctx context.Context, users auth.Users, user *auth.User, provider, identifier string) (*auth.User, error) {
	if users == nil || user == nil {
		return nil, fmt.Errorf("identifier store: users and user are required")
	}
	var created *auth.User
	err := s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		var err error
		created, err = users.CreateTx(ctx, tx, user)
		if err != nil {
			return err
		}
		return s.BindTx(ctx, tx, created.ID.String(), provider, identifier)
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (s *IdentifierStore) UpsertUserAndBind(
	ctx context.Context,
	users auth.Users,
	user *auth.User,
	provider, identifier string,
) (*auth.User, error) {
	if users == nil || user == nil {
		return nil, fmt.Errorf("identifier store: users and user are required")
	}
	var synced *auth.User
	err := s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		mappedID, lookupErr := s.findUserIDTx(ctx, tx, provider, identifier)
		switch {
		case lookupErr == nil:
			parsedID, parseErr := uuid.Parse(mappedID)
			if parseErr != nil {
				return fmt.Errorf("identifier store: mapped user ID is invalid: %w", parseErr)
			}
			if user.ID != uuid.Nil && user.ID != parsedID {
				return identifierConflict(provider)
			}
			profileSync, ok := users.(auth.ProviderProfileSyncRepository)
			if !ok {
				return fmt.Errorf("identifier store: users must support provider profile synchronization")
			}
			user.ID = parsedID
			var syncErr error
			synced, syncErr = profileSync.SyncProviderProfileTx(ctx, tx, user)
			if syncErr != nil {
				return syncErr
			}
		case bunrepo.IsRecordNotFound(lookupErr) || errors.Is(lookupErr, sql.ErrNoRows):
			var createErr error
			synced, createErr = users.CreateTx(ctx, tx, user)
			if createErr != nil {
				return createErr
			}
		default:
			return lookupErr
		}
		return s.BindTx(ctx, tx, synced.ID.String(), provider, identifier)
	})
	if err != nil {
		return nil, err
	}
	return synced, nil
}

func identifierConflict(provider string) error {
	conflict := auth.ErrIdentifierConflict.Clone()
	if conflict == nil {
		return auth.ErrIdentifierConflict
	}
	return conflict.WithMetadata(map[string]any{"provider": strings.TrimSpace(provider)})
}

func (s *IdentifierStore) Delete(ctx context.Context, userID, provider, identifier string) error {
	provider = strings.TrimSpace(provider)
	identifier = strings.TrimSpace(identifier)
	if provider == "" || identifier == "" {
		return fmt.Errorf("identifier store: provider and identifier are required")
	}

	parsedID, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return fmt.Errorf("identifier store: invalid user ID: %w", err)
	}

	_, err = s.db.NewDelete().
		Model((*IdentifierModel)(nil)).
		Where("user_id = ? AND provider = ? AND identifier = ?", parsedID, provider, identifier).
		Exec(ctx)
	return err
}

var _ auth.IdentifierStore = (*IdentifierStore)(nil)
var _ auth.ImmutableIdentifierStore = (*IdentifierStore)(nil)
var _ auth.TransactionalIdentifierStore = (*IdentifierStore)(nil)
var _ auth.TransactionalIdentifierSyncStore = (*IdentifierStore)(nil)
