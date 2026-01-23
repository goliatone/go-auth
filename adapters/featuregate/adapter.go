package goauthadapter

import (
	"context"
	"sort"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-featuregate/gate"
)

const defaultActorRefType = "user"

// ActorExtractor extracts an auth.ActorContext from context.
type ActorExtractor func(context.Context) (*auth.ActorContext, bool)

// RoleMapper builds role identifiers from ActorContext.
type RoleMapper func(actor *auth.ActorContext) []string

// PermMapper builds permission identifiers from ActorContext.
type PermMapper func(actor *auth.ActorContext) []string

// PermissionFormatter formats a resource/role pair into a permission string.
type PermissionFormatter func(resource, role string) string

// Option customizes ClaimsProvider behavior.
type Option func(*ClaimsProvider)

// ClaimsProvider derives feature claims from go-auth actor context.
type ClaimsProvider struct {
	extractor     ActorExtractor
	roleMapper    RoleMapper
	permMapper    PermMapper
	permFormatter PermissionFormatter
}

// NewClaimsProvider builds a claims provider using go-auth's actor context extractor.
func NewClaimsProvider(opts ...Option) *ClaimsProvider {
	provider := &ClaimsProvider{
		extractor:     auth.ActorFromContext,
		permFormatter: defaultPermissionFormatter,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(provider)
		}
	}
	if provider.extractor == nil {
		provider.extractor = auth.ActorFromContext
	}
	if provider.permFormatter == nil {
		provider.permFormatter = defaultPermissionFormatter
	}
	if provider.roleMapper == nil {
		provider.roleMapper = defaultRoleMapper
	}
	if provider.permMapper == nil {
		provider.permMapper = defaultPermMapper(provider.permFormatter)
	}
	return provider
}

// WithActorExtractor overrides the actor context extractor.
func WithActorExtractor(extractor ActorExtractor) Option {
	return func(provider *ClaimsProvider) {
		if provider == nil {
			return
		}
		provider.extractor = extractor
	}
}

// WithRoleMapper overrides the default role mapper.
func WithRoleMapper(mapper RoleMapper) Option {
	return func(provider *ClaimsProvider) {
		if provider == nil {
			return
		}
		provider.roleMapper = mapper
	}
}

// WithPermMapper overrides the default permission mapper.
func WithPermMapper(mapper PermMapper) Option {
	return func(provider *ClaimsProvider) {
		if provider == nil {
			return
		}
		provider.permMapper = mapper
	}
}

// WithPermissionFormatter customizes the resource/role permission formatter.
func WithPermissionFormatter(format PermissionFormatter) Option {
	return func(provider *ClaimsProvider) {
		if provider == nil {
			return
		}
		provider.permFormatter = format
	}
}

// ClaimsFromContext implements gate.ClaimsProvider.
func (p *ClaimsProvider) ClaimsFromContext(ctx context.Context) (gate.ActorClaims, error) {
	if p == nil || p.extractor == nil {
		return gate.ActorClaims{}, nil
	}
	actor, ok := p.extractor(ctx)
	if !ok || actor == nil {
		return gate.ActorClaims{}, nil
	}
	return claimsFromActor(actor, p.roleMapper, p.permMapper), nil
}

// ClaimsFromActor builds ActorClaims from an auth.ActorContext using defaults.
func ClaimsFromActor(actor *auth.ActorContext) gate.ActorClaims {
	return claimsFromActor(actor, defaultRoleMapper, defaultPermMapper(defaultPermissionFormatter))
}

func claimsFromActor(actor *auth.ActorContext, roleMapper RoleMapper, permMapper PermMapper) gate.ActorClaims {
	if actor == nil {
		return gate.ActorClaims{}
	}
	subjectID := actor.ActorID
	if subjectID == "" {
		subjectID = actor.Subject
	}
	claims := gate.ActorClaims{
		SubjectID: subjectID,
		TenantID:  actor.TenantID,
		OrgID:     actor.OrganizationID,
	}
	if roleMapper != nil {
		claims.Roles = roleMapper(actor)
	}
	if permMapper != nil {
		claims.Perms = permMapper(actor)
	}
	return claims
}

func defaultRoleMapper(actor *auth.ActorContext) []string {
	if actor == nil || actor.Role == "" {
		return nil
	}
	return []string{actor.Role}
}

func defaultPermMapper(format PermissionFormatter) PermMapper {
	return func(actor *auth.ActorContext) []string {
		if actor == nil || len(actor.ResourceRoles) == 0 {
			return nil
		}
		formatter := format
		if formatter == nil {
			formatter = defaultPermissionFormatter
		}
		resources := make([]string, 0, len(actor.ResourceRoles))
		for resource := range actor.ResourceRoles {
			resources = append(resources, resource)
		}
		sort.Strings(resources)
		perms := make([]string, 0, len(actor.ResourceRoles))
		for _, resource := range resources {
			role := actor.ResourceRoles[resource]
			if role == "" {
				continue
			}
			perms = append(perms, formatter(resource, role))
		}
		if len(perms) == 0 {
			return nil
		}
		return perms
	}
}

func defaultPermissionFormatter(resource, role string) string {
	return resource + ":" + role
}

// ClaimsExtractor returns actor context to derive permissions.
type ClaimsExtractor func(context.Context) (*auth.ActorContext, bool)

// PermConflictResolver combines claims perms with derived perms.
type PermConflictResolver func(existing, derived []string) []string

// PermOption customizes permission provider behavior.
type PermOption func(*PermissionProvider)

// PermissionProvider derives permissions from claims and actor context.
type PermissionProvider struct {
	extractor        ClaimsExtractor
	conflictResolver PermConflictResolver
}

// NewPermissionProvider builds a permission provider using go-auth's actor context extractor.
func NewPermissionProvider(opts ...PermOption) *PermissionProvider {
	provider := &PermissionProvider{
		extractor:        auth.ActorFromContext,
		conflictResolver: mergePerms,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(provider)
		}
	}
	if provider.extractor == nil {
		provider.extractor = auth.ActorFromContext
	}
	if provider.conflictResolver == nil {
		provider.conflictResolver = mergePerms
	}
	return provider
}

// WithClaimsExtractor overrides the claims extractor used to derive permissions.
func WithClaimsExtractor(extractor ClaimsExtractor) PermOption {
	return func(provider *PermissionProvider) {
		if provider == nil {
			return
		}
		provider.extractor = extractor
	}
}

// WithPermConflictResolver overrides how derived permissions are merged.
func WithPermConflictResolver(resolver PermConflictResolver) PermOption {
	return func(provider *PermissionProvider) {
		if provider == nil {
			return
		}
		provider.conflictResolver = resolver
	}
}

// Permissions implements gate.PermissionProvider.
func (p *PermissionProvider) Permissions(ctx context.Context, claims gate.ActorClaims) ([]string, error) {
	if p == nil {
		return claims.Perms, nil
	}
	var derived []string
	if p.extractor != nil {
		actor, ok := p.extractor(ctx)
		if ok && actor != nil {
			derived = defaultPermMapper(defaultPermissionFormatter)(actor)
		}
	}
	if p.conflictResolver == nil {
		return mergePerms(claims.Perms, derived), nil
	}
	return p.conflictResolver(claims.Perms, derived), nil
}

func mergePerms(existing, derived []string) []string {
	if len(existing) == 0 && len(derived) == 0 {
		return nil
	}
	merged := make([]string, 0, len(existing)+len(derived))
	merged = append(merged, existing...)
	merged = append(merged, derived...)
	return merged
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
		Type: defaultActorRefType,
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

var _ gate.ClaimsProvider = (*ClaimsProvider)(nil)
var _ gate.PermissionProvider = (*PermissionProvider)(nil)
