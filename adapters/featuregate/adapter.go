package goauthadapter

import (
	"context"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-featuregate/gate"
)

// ActorExtractor extracts an auth.ActorContext from context.
type ActorExtractor func(context.Context) (*auth.ActorContext, bool)

// Option customizes the scope resolver behavior.
type Option func(*ScopeResolver)

// ScopeResolver derives feature scopes from go-auth actor context.
type ScopeResolver struct {
	extractor ActorExtractor
}

// NewScopeResolver builds a resolver using go-auth's actor context extractor.
func NewScopeResolver(opts ...Option) *ScopeResolver {
	resolver := &ScopeResolver{
		extractor: auth.ActorFromContext,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(resolver)
		}
	}
	if resolver.extractor == nil {
		resolver.extractor = auth.ActorFromContext
	}
	return resolver
}

// WithActorExtractor overrides the actor context extractor.
func WithActorExtractor(extractor ActorExtractor) Option {
	return func(resolver *ScopeResolver) {
		if resolver == nil {
			return
		}
		resolver.extractor = extractor
	}
}

// Resolve implements gate.ScopeResolver.
func (r *ScopeResolver) Resolve(ctx context.Context) (gate.ScopeSet, error) {
	if r == nil || r.extractor == nil {
		return gate.ScopeSet{}, nil
	}
	actor, ok := r.extractor(ctx)
	if !ok || actor == nil {
		return gate.ScopeSet{}, nil
	}
	return ScopeFromActor(actor), nil
}

// ScopeFromActor builds a ScopeSet from an auth.ActorContext.
func ScopeFromActor(actor *auth.ActorContext) gate.ScopeSet {
	if actor == nil {
		return gate.ScopeSet{}
	}
	userID := actor.ActorID
	if userID == "" {
		userID = actor.Subject
	}
	return gate.ScopeSet{
		TenantID: actor.TenantID,
		OrgID:    actor.OrganizationID,
		UserID:   userID,
	}
}

// ActorRefFromActor builds an ActorRef from an auth.ActorContext.
func ActorRefFromActor(actor *auth.ActorContext) gate.ActorRef {
	if actor == nil {
		return gate.ActorRef{}
	}
	id := actor.ActorID
	if id == "" {
		id = actor.Subject
	}
	return gate.ActorRef{
		ID:   id,
		Type: actor.Subject,
		Name: actor.Role,
	}
}

// ActorRefFromContext extracts an ActorRef from context.
func ActorRefFromContext(ctx context.Context) (gate.ActorRef, bool) {
	actor, ok := auth.ActorFromContext(ctx)
	if !ok || actor == nil {
		return gate.ActorRef{}, false
	}
	return ActorRefFromActor(actor), true
}

var _ gate.ScopeResolver = (*ScopeResolver)(nil)
