package auth

import (
	"context"

	"github.com/goliatone/go-auth/middleware/jwtware"
)

// ValidationListener aliases the jwtware listener so consumers can use auth helpers directly.
type ValidationListener = jwtware.ValidationListener

// ContextEnricherAdapter adapts jwtware.AuthClaims to auth.AuthClaims and stores
// claims + actor context in the standard context for downstream guard usage.
func ContextEnricherAdapter(c context.Context, claims jwtware.AuthClaims) context.Context {
	authClaims, ok := claims.(AuthClaims)
	if !ok {
		return c
	}

	ctxWithClaims := WithClaimsContext(c, authClaims)

	if actor := ActorContextFromClaims(authClaims); actor != nil {
		return WithActorContext(ctxWithClaims, actor)
	}

	return ctxWithClaims
}

// RegisterValidationListeners appends listeners to a jwtware.Config in a safe, reusable way.
func RegisterValidationListeners(cfg *jwtware.Config, listeners ...ValidationListener) {
	if cfg == nil || len(listeners) == 0 {
		return
	}
	cfg.ValidationListeners = append(cfg.ValidationListeners, listeners...)
}
