package oidc

import (
	"context"

	auth "github.com/goliatone/go-auth"
)

// SessionCreatorHandoff adapts the provider-neutral session creator to the
// OIDC callback handoff without exposing repository or token-vault internals.
type SessionCreatorHandoff struct {
	Creator auth.ProviderSessionCreator
}

func (h SessionCreatorHandoff) CreateProviderSession(ctx context.Context, principal auth.AuthenticatedPrincipal, tokens auth.ProviderTokenSet) (ProviderSessionHandoffResult, error) {
	if h.Creator == nil {
		return ProviderSessionHandoffResult{}, ErrInvalidConfig
	}
	created, err := h.Creator.CreateProviderSession(ctx, principal, tokens)
	if err != nil {
		return ProviderSessionHandoffResult{}, err
	}
	return NewProviderSessionHandoffResult(created.Handle, created.Session.LocalSessionID)
}

var _ ProviderSessionHandoff = SessionCreatorHandoff{}
