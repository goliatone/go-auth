package auth

import (
	"context"

	"github.com/goliatone/go-router"
)

var userCtxKey = &contextKey{"user"}
var claimsCtxKey = &contextKey{"claims"}
var actorCtxKey = &contextKey{"actor"}

type contextKey struct {
	name string
}

// ActorContext captures normalized actor metadata for downstream policy/guard layers.
type ActorContext struct {
	ActorID        string
	Subject        string
	Role           string
	ResourceRoles  map[string]string
	TenantID       string
	OrganizationID string
	Metadata       map[string]any
	ImpersonatorID string
	IsImpersonated bool
}

var (
	tenantMetadataKeys       = []string{"tenant_id", "tenant", "default_tenant", "default_tenant_id"}
	organizationMetadataKeys = []string{"organization_id", "org_id", "org"}
	impersonatorMetadataKeys = []string{"impersonator_id", "impersonation_actor_id"}
	impersonatedFlagKeys     = []string{"impersonated", "is_impersonated"}
)

type resourceRoleCarrier interface {
	ResourceRoles() map[string]string
}

type claimsMetadataCarrier interface {
	ClaimsMetadata() map[string]any
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

// WithActorContext stores the ActorContext in the provided context.
func WithActorContext(ctx context.Context, actor *ActorContext) context.Context {
	if ctx == nil || actor == nil {
		return ctx
	}
	return context.WithValue(ctx, actorCtxKey, actor)
}

// ActorFromContext extracts the ActorContext from the standard context.
func ActorFromContext(ctx context.Context) (*ActorContext, bool) {
	if ctx == nil {
		return nil, false
	}
	raw, ok := ctx.Value(actorCtxKey).(*ActorContext)
	return raw, ok
}

// ActorFromRouterContext extracts the ActorContext from a router context by reading the underlying standard context.
func ActorFromRouterContext(ctx router.Context) (*ActorContext, bool) {
	if ctx == nil {
		return nil, false
	}
	return ActorFromContext(ctx.Context())
}

// ActorContextFromClaims normalizes actor metadata from AuthClaims into an ActorContext structure.
func ActorContextFromClaims(claims AuthClaims) *ActorContext {
	if claims == nil {
		return nil
	}

	actor := &ActorContext{
		ActorID: claims.UserID(),
		Subject: claims.Subject(),
		Role:    claims.Role(),
	}

	if actor.ActorID == "" {
		actor.ActorID = actor.Subject
	}

	if rrCarrier, ok := claims.(resourceRoleCarrier); ok {
		if roles := rrCarrier.ResourceRoles(); len(roles) > 0 {
			actor.ResourceRoles = cloneStringMap(roles)
		}
	}

	if metaCarrier, ok := claims.(claimsMetadataCarrier); ok {
		if metadata := metaCarrier.ClaimsMetadata(); len(metadata) > 0 {
			actor.Metadata = cloneAnyMap(metadata)
			actor.TenantID = firstString(metadata, tenantMetadataKeys)
			actor.OrganizationID = firstString(metadata, organizationMetadataKeys)
			actor.ImpersonatorID = firstString(metadata, impersonatorMetadataKeys)
			if actor.ImpersonatorID != "" {
				actor.IsImpersonated = true
			}
			for _, key := range impersonatedFlagKeys {
				if flag, ok := metadata[key].(bool); ok && flag {
					actor.IsImpersonated = true
					break
				}
			}
		}
	}

	return actor
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func cloneAnyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func firstString(metadata map[string]any, keys []string) string {
	for _, key := range keys {
		if val, ok := metadata[key]; ok {
			if str, ok := val.(string); ok && str != "" {
				return str
			}
		}
	}
	return ""
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
