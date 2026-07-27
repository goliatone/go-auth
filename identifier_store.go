package auth

import (
	"context"

	"github.com/uptrace/bun"
)

// IdentifierStore maps external provider identifiers to local user IDs.
type IdentifierStore interface {
	FindUserID(ctx context.Context, provider, identifier string) (string, error)
	Upsert(ctx context.Context, userID, provider, identifier string) error
	Delete(ctx context.Context, userID, provider, identifier string) error
}

// ImmutableIdentifierStore binds an external provider identifier exactly once.
// Repeating the same binding is idempotent; binding it to a different user must
// return ErrIdentifierConflict.
type ImmutableIdentifierStore interface {
	IdentifierStore
	Bind(ctx context.Context, userID, provider, identifier string) error
}

// TransactionalIdentifierStore can create a user and bind its external
// identifier in one database transaction.
type TransactionalIdentifierStore interface {
	ImmutableIdentifierStore
	CreateUserAndBind(ctx context.Context, users Users, user *User, provider, identifier string) (*User, error)
}

// TransactionalIdentifierSyncStore can upsert provider-owned local profile
// data and preserve its immutable external binding in one transaction.
// Provider-driven sync must require this capability because compensating an
// update cannot safely reconstruct the previous user record.
type TransactionalIdentifierSyncStore interface {
	ImmutableIdentifierStore
	UpsertUserAndBind(ctx context.Context, users Users, user *User, provider, identifier string) (*User, error)
}

// ProviderProfileSyncRepository is the user-store capability required when a
// provider-driven sync updates an already-linked local user. Implementations
// must update provider-owned profile fields only; lifecycle and authorization
// fields remain under their dedicated state/version writers.
type ProviderProfileSyncRepository interface {
	SyncProviderProfileTx(ctx context.Context, tx bun.IDB, profile *User) (*User, error)
}
