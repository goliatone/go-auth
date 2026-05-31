package auth

import "context"

// IdentifierStore maps external provider identifiers to local user IDs.
type IdentifierStore interface {
	FindUserID(ctx context.Context, provider, identifier string) (string, error)
	Upsert(ctx context.Context, userID, provider, identifier string) error
}
