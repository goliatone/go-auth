package repository

import (
	"context"
	"database/sql"
	"errors"
	"log"

	"github.com/goliatone/go-auth/auth"
	"github.com/goliatone/go-repository-bun"
	"github.com/uptrace/bun"
)

type mngr struct {
	db             *bun.DB
	users          auth.Users
	passwordResets repository.Repository[*auth.PasswordReset]
}

func NewRepositoryManager(db *bun.DB) auth.RepositoryManager {
	return &mngr{
		users:          auth.NewUsersRepository(db),
		passwordResets: auth.NewPasswordResetsRepository(db),
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

func (m mngr) Users() auth.Users {
	return m.users
}

func (m mngr) PasswordResets() repository.Repository[*auth.PasswordReset] {
	return m.passwordResets
}
