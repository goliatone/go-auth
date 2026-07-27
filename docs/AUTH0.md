# Auth0 Integration

This guide describes the Auth0 integration for go-auth, including the minimal
token validation flow and the optional sync track for local mirroring.

## Overview

There are two opt-in tracks:

- **Minimal** (`provider/auth0`): Validate Auth0-issued JWTs and map claims into
  go-auth `JWTClaims`.
- **Sync** (`provider/auth0/sync`): Optionally mirror Auth0 users into the local
  database with identifier mapping.

Both tracks are additive and use `WithTokenValidator`, so existing local auth
flows remain intact.

Auth0 also fits the generic OIDC SSO model for browser login. Keep using
`provider/auth0` for Auth0-specific JWT validation, management API, and sync
workflows. Use a generic OIDC preset for browser SSO when Auth0 is acting as a
standard OIDC provider and no Auth0-specific management behavior is needed.

Provider package placement follows `provider/README.md`: thin OIDC presets live
under `provider/oidc/preset`; top-level provider packages are reserved for
custom validation, sync, management APIs, non-OIDC behavior, or other
provider-specific code.

## Minimal Setup (Auth0 as Token Issuer)

```go
import (
    "github.com/goliatone/go-auth"
    "github.com/goliatone/go-auth/provider/auth0"
    "github.com/goliatone/go-auth/repository"
)

repoManager := repository.NewRepositoryManager(bunDB)
userProvider := auth.NewUserProvider(repoManager.Users())
authenticator := auth.NewAuthenticator(userProvider, cfg.Auth)

auth0Validator, err := auth0.NewTokenValidator(auth0.Config{
    Domain:   "your-tenant.auth0.com",
    Audience: []string{"https://api.yourapp.com"},
    ClaimsMapper: &auth0.Auth0ClaimsMapper{
        Namespace: "https://acme.example/",
    },
})
if err != nil {
    return err
}

// Accept only Auth0-issued tokens.
authenticator = authenticator.WithTokenValidator(auth0Validator)

// Or accept both Auth0 + local go-auth tokens.
composite := auth.NewMultiTokenValidator(auth0Validator, authenticator.TokenService())
authenticator = authenticator.WithTokenValidator(composite)
```

## Sync Setup (Optional Local Mirroring)

The sync track uses `provider/auth0/sync` to keep a local user record aligned
with Auth0. It relies on the identifier mapping table created by migrations.

```go
import (
    "context"

    "github.com/goliatone/go-auth"
    "github.com/goliatone/go-auth/provider/auth0"
    auth0sync "github.com/goliatone/go-auth/provider/auth0/sync"
    "github.com/goliatone/go-auth/repository"
)

repoManager := repository.NewRepositoryManager(bunDB)
userProvider := auth.NewUserProvider(repoManager.Users())
authenticator := auth.NewAuthenticator(userProvider, cfg.Auth)

auth0Validator, err := auth0.NewTokenValidator(auth0.Config{
    Domain:   "your-tenant.auth0.com",
    Audience: []string{"https://api.yourapp.com"},
})
if err != nil {
    return err
}
authenticator = authenticator.WithTokenValidator(auth0Validator)

identifierStore := auth0sync.NewIdentifierStore(bunDB) // implements auth.IdentifierStore
syncService := auth0sync.NewService(auth0sync.Config{
    Users:           repoManager.Users(),
    IdentifierStore: identifierStore,
    Provider:        auth0.IdentifierProviderAuth0,
})

mgmt, err := auth0sync.NewManagementClient(context.Background(), auth0sync.ManagementConfig{
    Domain:       "your-tenant.auth0.com",
    ClientID:     "m2m-client-id",
    ClientSecret: "m2m-client-secret",
})
if err != nil {
    return err
}

_, err = syncService.SyncByID(context.Background(), mgmt, "auth0|user-id")
if err != nil {
    return err
}
```

If you want `FindIdentityByIdentifier` to resolve Auth0 users and optionally
sync on lookup, use `auth0.NewIdentityProvider` with the same IdentifierStore.

## Migration Guide (user_identifiers)

Auth0 sync and generic OIDC SSO share the provider-neutral
`auth.IdentifierStore` contract. The Bun implementation lives at
`repository.NewIdentifierStore`; `provider/auth0/sync.NewIdentifierStore` is a
compatibility alias for existing Auth0 callers.

`user_identifiers` is the canonical mapping table for SSO provider-subject
links. Use provider plus subject for lookup before any email fallback. Optional
`users.external_id` fields are legacy enrichment and should not become the
primary lookup path.

Migration files:

- `data/sql/migrations/20240701090000_auth0_identifiers.up.sql`
- `data/sql/migrations/20240701090000_auth0_identifiers.down.sql`
- `data/sql/migrations/sqlite/20240701090000_auth0_identifiers.up.sql`
- `data/sql/migrations/sqlite/20240701090000_auth0_identifiers.down.sql`

For segmented registration use `auth.GetAuthExtrasMigrationsFS()` and register
it after `auth.GetCoreMigrationsFS()`.

Schema summary:

- `user_identifiers` includes `provider`, `identifier`, and `(provider, identifier)` uniqueness.
- `user_identifiers` adds an index on `(user_id, provider)` for lookups.
- `users.external_id` and `users.external_id_provider` are optional for primary mappings.

Existing Auth0 `user_identifiers` rows already match the generic SSO mapping
shape when `provider='auth0'` and `identifier` contains the Auth0 `sub`. No
schema migration is required to use the same rows from generic OIDC linking.

Identifier mappings are immutable. `Upsert` remains source-compatible but is
same-user idempotent and returns `auth.ErrIdentifierConflict` instead of
reassigning a provider subject to a different local user. Auth0 sync propagates
that conflict; callers must explicitly unlink a proven existing mapping before
an intentional migration.

## Error Normalization

Auth0 validation errors are normalized to go-auth errors and include metadata:

- Expired tokens map to `ErrTokenExpired`.
- Invalid or malformed tokens map to `ErrTokenMalformed`.
- Errors include `provider=auth0` and a `cause` string.

Use the helpers to check normalized errors:

```go
if auth.IsTokenExpiredError(err) {
    // handle expiration
}
if auth.IsMalformedError(err) {
    // handle malformed/invalid token
}
```

## HasUserUUID Helper

Auth0 `sub` values are not UUIDs. Use `HasUserUUID` to guard calls to
`Session.GetUserUUID`:

```go
session, _ := authenticator.SessionFromToken(token)
if auth.HasUserUUID(session) {
    userID, _ := session.GetUserUUID()
    _ = userID
}
```

## Examples

See:

- `examples/auth0/minimal.go`
- `examples/auth0/sync.go`
