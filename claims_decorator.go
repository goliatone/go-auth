package auth

import "context"

// ClaimsDecorator can mutate allowed JWT claim extensions before a token is signed.
// Implementations may only touch extension fields (e.g. Resources, Metadata) and
// must leave registered/identity claims untouched so core auth semantics stay stable.
type ClaimsDecorator interface {
	Decorate(ctx context.Context, identity Identity, claims *JWTClaims) error
}

// ClaimsDecoratorFunc adapts a function into a ClaimsDecorator.
type ClaimsDecoratorFunc func(ctx context.Context, identity Identity, claims *JWTClaims) error

// Decorate satisfies the ClaimsDecorator interface.
func (f ClaimsDecoratorFunc) Decorate(ctx context.Context, identity Identity, claims *JWTClaims) error {
	if f == nil {
		return nil
	}
	return f(ctx, identity, claims)
}

type noopClaimsDecorator struct{}

func (noopClaimsDecorator) Decorate(context.Context, Identity, *JWTClaims) error {
	return nil
}

func normalizeClaimsDecorator(d ClaimsDecorator) ClaimsDecorator {
	if d == nil {
		return noopClaimsDecorator{}
	}
	return d
}
