---
title: go-auth featuregate adapter refactor
status: draft
owner: go-auth / go-featuregate
scope: adapter API update for claims + scope chain
---

# go-auth featuregate adapter refactor

## Context

go-auth: /Users/goliatone/Development/GO/src/github.com/goliatone/go-auth
go-featuregate: /Users/goliatone/Development/GO/src/github.com/goliatone/go-featuregate

go-featuregate replaced `ScopeSet` and `ScopeResolver` with `ActorClaims`,
`ScopeChain`, and `ClaimsProvider`/`PermissionProvider`. The current adapter
implements `gate.ScopeResolver` and returns `gate.ScopeSet`, which no longer
compiles against the new API.

We also decided on Option 2 for role/permission mapping:

- `ActorContext.Role` -> `ActorClaims.Roles`
- `ActorContext.ResourceRoles` -> `ActorClaims.Perms` (namespaced strings)

`PermissionProvider` must be optional: some applications will rely entirely on
claims-derived perms, while others may want dynamic permission resolution. When
configured, it should support a conflict resolution strategy for claims perms.

## Goals

- Provide a `ClaimsProvider` adapter that maps `auth.ActorContext` to
  `gate.ActorClaims`.
- Support Option 2 role/perm mapping with a configurable permission formatter.
- Keep `PermissionProvider` optional and separate from claims resolution.
- Rely on go-featuregate role/perm normalization (no extra normalization here).
- Preserve existing `ActorRef` helpers (unless a change is explicitly desired).
- Keep dependencies minimal and avoid cycles.

## Non-goals

- Changing core go-auth `ActorContext` semantics.
- Defining a domain-specific permission taxonomy beyond a default formatter.
- Implementing storage or admin features.

## Current issues

- `ScopeResolver` and `ScopeSet` are removed from go-featuregate.
- The adapter returns `ScopeSet` and implements an obsolete interface.
- No path to populate role/perm scopes with the new chain.

## Proposed API

### New types

```go
// ClaimsProvider derives feature claims from go-auth actor context.
type ClaimsProvider struct {
    extractor ActorExtractor
    roleMapper RoleMapper
    permMapper PermMapper
}

// RoleMapper builds role identifiers from ActorContext.
type RoleMapper func(actor *auth.ActorContext) []string

// PermMapper builds permission identifiers from ActorContext.
type PermMapper func(actor *auth.ActorContext) []string
```

### Constructors and options

```go
func NewClaimsProvider(opts ...Option) *ClaimsProvider

func WithActorExtractor(extractor ActorExtractor) Option
func WithRoleMapper(mapper RoleMapper) Option
func WithPermMapper(mapper PermMapper) Option
func WithPermissionFormatter(format PermissionFormatter) Option
```

Defaults:

- `ActorExtractor`: `auth.ActorFromContext`
- `RoleMapper`: return `[]string{actor.Role}` when non-empty
- `PermMapper`: convert `ResourceRoles` into permissions with a formatter

### Permission formatting

Provide a simple default formatter:

```
resource:role
```

Example: `"org:admin"`, `"project:viewer"`.

Expose a convenience helper for customization:

```go
type PermissionFormatter func(resource, role string) string
func WithPermissionFormatter(format PermissionFormatter) Option
```

If no custom formatter is provided, the default `resource:role` formatter is
used. If `ResourceRoles` is empty, `Perms` should be nil.

### ClaimsProvider implementation

```go
func (p *ClaimsProvider) ClaimsFromContext(ctx context.Context) (gate.ActorClaims, error)
```

Logic:

1. Extract `ActorContext` via `ActorExtractor`.
2. If missing, return zero `ActorClaims`.
3. `SubjectID` := `ActorID` if present, else `Subject`.
4. `TenantID` := `actor.TenantID`
5. `OrgID` := `actor.OrganizationID`
6. `Roles` := `RoleMapper(actor)`
7. `Perms` := `PermMapper(actor)`

### Optional PermissionProvider

Make this optional and separate from `ClaimsProvider` (aligns with
`gate.PermissionProvider`):

```go
// PermissionProvider derives permissions from claims.
type PermissionProvider struct {
    extractor ClaimsExtractor
    conflictResolver PermConflictResolver
}

// ClaimsExtractor returns auth claims or actor context to derive perms.
type ClaimsExtractor func(context.Context) (*auth.ActorContext, bool)

func NewPermissionProvider(opts ...PermOption) *PermissionProvider

// PermConflictResolver combines claims perms with derived perms.
type PermConflictResolver func(existing, derived []string) []string

func WithPermConflictResolver(resolver PermConflictResolver) PermOption
```

```go
func (p *PermissionProvider) Permissions(ctx context.Context, claims gate.ActorClaims) ([]string, error)
```

Defaults:

- `ClaimsExtractor`: `auth.ActorFromContext`
- `PermConflictResolver`: merge (append) claims perms + derived perms

Notes:

- If no permission provider is configured by the caller, permissions only come
  from `ActorClaims.Perms`.
- The resolver always merges provider output with `claims.Perms` inside
  go-featuregate; for override semantics, either ensure `ClaimsProvider` leaves
  `Perms` empty or implement a custom provider that returns only the intended
  delta and relies on go-featuregate dedupe.

## Compatibility and migration

- Remove `ScopeResolver` and `ScopeFromActor` APIs.
- Add `ClaimsProvider` and `ClaimsFromActor` helpers.
- Update call sites to:

```go
resolver.New(
    resolver.WithClaimsProvider(goauthadapter.NewClaimsProvider(...)),
)
```

If dynamic perms are needed:

```go
resolver.New(
    resolver.WithClaimsProvider(goauthadapter.NewClaimsProvider(...)),
    resolver.WithPermissionProvider(goauthadapter.NewPermissionProvider(...)),
)
```

## Implementation plan

1. Replace `ScopeResolver` with `ClaimsProvider` and new options.
2. Add `ClaimsFromActor` helper (replaces `ScopeFromActor`).
3. Add `WithRoleMapper`, `WithPermMapper`, and optional permission formatter.
4. Update `ActorRefFromActor` to use a stable `Type` of `"user"`; keep
   `ActorRefFromContext` unchanged.
5. Update tests to cover:
   - nil/empty actor contexts
   - role mapping (`ActorContext.Role`)
   - resource role mapping into `Perms` with default formatter
   - custom formatter
   - optional permission provider behavior
   - conflict resolver default (merge) and custom strategy
6. Update README/docs in go-auth adapter folder (if present) with new usage.

## Decisions

- `ActorRefFromActor` uses a stable `Type` of `"user"` instead of `actor.Subject`.
