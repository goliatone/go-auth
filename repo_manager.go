package auth

import (
	"context"
	"database/sql"
	"errors"
	"log"

	"github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// RepositoryManager exposes all repositories
type RepositoryManager interface {
	repository.Validator
	repository.TransactionManager
	Users() Users
	PasswordResets() repository.Repository[*PasswordReset]
}

func NewPasswordResetsRepository(db *bun.DB) repository.Repository[*PasswordReset] {
	handlers := repository.ModelHandlers[*PasswordReset]{
		NewRecord: func() *PasswordReset {
			return &PasswordReset{}
		},
		GetID: func(record *PasswordReset) uuid.UUID {
			if record == nil {
				return uuid.Nil
			}
			return record.ID
		},
		SetID: func(record *PasswordReset, id uuid.UUID) {
			record.ID = id
		},
		GetIdentifier: func() string {
			return "email"
		},
	}
	return repository.NewRepository(db, handlers)
}

type mngr struct {
	db             *bun.DB
	users          Users
	passwordResets repository.Repository[*PasswordReset]
}

func NewRepositoryManager(db *bun.DB) RepositoryManager {
	return &mngr{
		db:             db,
		users:          NewUsersRepository(db),
		passwordResets: NewPasswordResetsRepository(db),
	}
}

func (m mngr) Validate() error {
	if m.users == nil {
		return errors.New("repository users should be initialized")
	}

	if m.passwordResets == nil {
		return errors.New("repository passwordResets should be initialized")
	}

	return nil
}

func (m mngr) MustValidate() {
	if err := m.Validate(); err != nil {
		log.Panic(err)
	}
}

func (m mngr) RunInTx(ctx context.Context, opts *sql.TxOptions, f func(ctx context.Context, tx bun.Tx) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return m.db.RunInTx(ctx, opts, f)
	}
}

func (m mngr) Users() Users {
	return m.users
}

func (m mngr) PasswordResets() repository.Repository[*PasswordReset] {
	return m.passwordResets
}
