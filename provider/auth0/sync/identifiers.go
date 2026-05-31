package sync

import (
	"github.com/goliatone/go-auth"
	authrepo "github.com/goliatone/go-auth/repository"
	"github.com/uptrace/bun"
)

type IdentifierModel = authrepo.IdentifierModel
type IdentifierStore = authrepo.IdentifierStore

func NewIdentifierStore(db *bun.DB) *IdentifierStore {
	return authrepo.NewIdentifierStore(db)
}

// Deprecated: use auth.IdentifierStore for provider-neutral identifier mapping.
type Auth0IdentifierStore = auth.IdentifierStore

var _ auth.IdentifierStore = (*IdentifierStore)(nil)
