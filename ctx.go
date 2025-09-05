package auth

import (
	"context"

	"github.com/goliatone/go-router"
)

var userCtxKey = &contextKey{"user"}
var claimsCtxKey = &contextKey{"claims"}

type contextKey struct {
	name string
}

// WithContext sets the User in the given context
func WithContext(r context.Context, user *User) context.Context {
	return context.WithValue(r, userCtxKey, user)
}

// FromContext finds the user from the context.
func FromContext(ctx context.Context) (*User, bool) {
	raw, ok := ctx.Value(userCtxKey).(*User)
	return raw, ok
}

// WithClaimsContext sets the AuthClaims in the given context
func WithClaimsContext(r context.Context, claims AuthClaims) context.Context {
	return context.WithValue(r, claimsCtxKey, claims)
}

// GetClaims extracts the AuthClaims from the standard context
func GetClaims(ctx context.Context) (AuthClaims, bool) {
	raw, ok := ctx.Value(claimsCtxKey).(AuthClaims)
	return raw, ok
}

// GetRouterClaims extracts the AuthClaims from the router context
func GetRouterClaims(ctx router.Context, key string) (AuthClaims, bool) {
	if key == "" {
		key = "user" // Default key used by JWT middleware
	}
	raw := ctx.Locals(key)
	if raw == nil {
		return nil, false
	}
	claims, ok := raw.(AuthClaims)
	return claims, ok
}

// Can is a convenience function to check permissions directly from the standard context
// Use CanFromRouter for router-based contexts.
func Can(ctx context.Context, resource, permission string) bool {
	claims, ok := GetClaims(ctx)
	if !ok {
		return false
	}

	switch permission {
	case "read":
		return claims.CanRead(resource)
	case "edit":
		return claims.CanEdit(resource)
	case "create":
		return claims.CanCreate(resource)
	case "delete":
		return claims.CanDelete(resource)
	default:
		return false
	}
}

// CanFromRouter is a convenience function to check permissions directly from the router context
func CanFromRouter(ctx router.Context, resource, permission string) bool {
	claims, ok := GetRouterClaims(ctx, "")
	if !ok {
		return false
	}

	switch permission {
	case "read":
		return claims.CanRead(resource)
	case "edit":
		return claims.CanEdit(resource)
	case "create":
		return claims.CanCreate(resource)
	case "delete":
		return claims.CanDelete(resource)
	default:
		return false
	}
}
