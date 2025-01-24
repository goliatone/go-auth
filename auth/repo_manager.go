package auth

import (
	"github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// RepositoryManager exposes all repositories
type RepositoryManager interface {
	repository.Validator
	repository.TransactionManager
	Users() repository.Repository[*User]
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

func NewUsersRepository(db *bun.DB) repository.Repository[*User] {
	handlers := repository.ModelHandlers[*User]{
		NewRecord: func() *User {
			return &User{}
		},
		GetID: func(record *User) uuid.UUID {
			if record == nil {
				return uuid.Nil
			}

			return record.ID
		},
		SetID: func(record *User, id uuid.UUID) {
			record.ID = id
		},
		GetIdentifier: func() string {
			return "email"
		},
	}
	return repository.NewRepository(db, handlers)
}

var ResetUserPasswordSQL = `UPDATE "users" AS "usr"
SET
	"is_email_verified" = TRUE,
	"password_hash" = ?
WHERE
	"usr"."deleted_at" IS NULL
AND (
	"usr"."id" = ?
) RETURNING *;`
