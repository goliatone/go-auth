# Featuregate Adapter

## What it does

Maps `go-auth` actor context into `go-featuregate` claims and optional permissions.

## When to use

- Use this adapter when your app stores `auth.ActorContext` in `context.Context`.
- Use it when you want to drive feature access from actor roles and resource roles.
- Use the permission provider when permissions are not fully present in claims.

## How to use

### Claims only

```go
claimsProvider := goauthadapter.NewClaimsProvider()
resolver := gate.NewResolver(
	gate.WithClaimsProvider(claimsProvider),
)
```

### Claims with custom permission formatting

```go
claimsProvider := goauthadapter.NewClaimsProvider(
	goauthadapter.WithPermissionFormatter(func(resource, role string) string {
		return resource + ":" + role
	}),
)
```

### Claims + permission provider

```go
claimsProvider := goauthadapter.NewClaimsProvider()
permProvider := goauthadapter.NewPermissionProvider()

resolver := gate.NewResolver(
	gate.WithClaimsProvider(claimsProvider),
	gate.WithPermissionProvider(permProvider),
)
```

## Defaults

- `ActorExtractor`: `auth.ActorFromContext`
- `RoleMapper`: `[actor.Role]` when non-empty
- `PermMapper`: `ActorContext.ResourceRoles` formatted as `resource:role`
- `PermissionProvider`: merges derived perms with `claims.Perms`

