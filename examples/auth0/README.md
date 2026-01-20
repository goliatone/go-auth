# Auth0 Examples

This folder contains Auth0 wiring examples:

- `minimal.go`: Auth0 token validation with optional composite validation.
- `sync.go`: Sync service and management client wiring for local mirroring.

Apply the Auth0 sync migrations before using the sync example:

- `data/sql/migrations/0001_auth0_identifiers.up.sql`
- `data/sql/migrations/sqlite/0001_auth0_identifiers.up.sql`
