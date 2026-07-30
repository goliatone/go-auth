# go-auth examples

This directory contains one runnable browser application and several
integration-wiring packages. The distinction matters:

| Example | Kind | What it demonstrates |
|---|---|---|
| [`main.go`](main.go) | Runnable application | Local password auth, CSRF-protected forms, JWT cookies, protected routes, SQLite migrations and fixtures, templates, and resource-role guards |
| [`auth0/minimal.go`](auth0/minimal.go) | Host wiring | Auth0 access-token validation, optionally composed with local go-auth tokens |
| [`auth0/sync.go`](auth0/sync.go) | Host wiring | Auth0 Management API access and local user/identifier synchronization |
| [`supabase/supabase.go`](supabase/supabase.go) | Host wiring | Hardened Supabase OIDC, provider-session operations, admin operations, and authorization decisions |
| [`extensions/extensions.go`](extensions/extensions.go) | Host wiring | Activity sinks, user lifecycle transitions, and tenant/resource claims decoration |
| [`extensions/social_login.go`](extensions/social_login.go) | Host wiring | GitHub and Google login, local account creation/linking, and social HTTP routes |

The host-wiring examples compile as library packages. They deliberately leave
the HTTP host, database ownership, secret loading, and application policy to
the consuming service.

## Prerequisites

- Go 1.26 or a compatible newer toolchain.
- Node.js and npm only when rebuilding the example CSS.
- Provider accounts and credentials only for the Auth0, Supabase, GitHub, or
  Google integrations.

Run commands from this directory because the runnable application loads
[`config/app.json`](config/app.json) relative to its working directory:

```sh
cd examples
```

## Runnable local web application

### Quick start

The committed assets and generated Go configuration are sufficient to run the
application:

```sh
go mod download
go run .
```

Open <http://127.0.0.1:8572>.

The application creates `test.db`, applies the embedded SQLite migrations, and
loads [`data/fixtures/users.yml`](data/fixtures/users.yml). Fixture-owned user
rows are truncated and reseeded on each startup, so treat this database as
disposable development data.

Seeded accounts:

| Account | Password | Role |
|---|---|---|
| `admin@example.com` | `adminpass` | `owner` |
| `member@example.com` | `userpass` | `member` |

These credentials and the signing key in `config/app.json` are intentionally
development-only.

### Routes to try

| Route | Access | Purpose |
|---|---|---|
| `/` | Public | Home page |
| `/test` | Public | Template and asset rendering |
| `/login` | Public | CSRF-protected local login |
| `/register` | Public | Local registration |
| `/password-reset` | Public | Password-reset request and completion flow |
| `/logout` | CSRF-protected `POST` | Clear the local session |
| `/me` | Authenticated | View or update the current profile |
| `/protected-page` | Authenticated | Inspect the normalized actor context |
| `/admin/users` | Authenticated and guarded | Demonstrate tenant/resource authorization |

The login, registration, password-reset, and logout mutations use the shared
browser CSRF middleware. Protected routes accept the local JWT from the
`Authorization` header or the `jwt` cookie, as configured in
`config/app.json`.

`/admin/users` is intentionally stricter than ordinary authentication: the
example guard requires tenant context before evaluating the global or
resource-specific role. A plain seeded login may therefore receive `403`; use
the claims-decorator example below when experimenting with tenant-aware access.

### Configuration

The application currently loads one file:

```text
config/app.json
```

Important settings:

- `persistence.dsn` controls the SQLite file.
- `auth.signing_key`, issuer, audience, expiration, and token lookup configure
  local JWTs.
- `views.dir_fs` and `views.assets_dir` select templates and static assets.
- `views.url_prefix` mounts the assets under `/assets`.
- The listen address is currently fixed at `:8572` in `main.go`.

The checked-in configuration is for local development. Do not reuse its
signing key in a deployed application. This example does not currently add an
environment provider to `go-config`, so edit or replace `config/app.json` when
testing other values.

### Rebuild frontend assets

The templates use Tailwind CSS. Dependencies are pinned by
[`package-lock.json`](package-lock.json):

```sh
npm ci
npm run build:css
go run .
```

The CSS command compiles [`assets/styles.css`](assets/styles.css) to
`public/css/main.css`.

### Regenerate Go configuration

[`config/config_structs.go`](config/config_structs.go) and
[`config/config_getters.go`](config/config_getters.go) are generated from
`config/app.json` and [`config/overrides.yml`](config/overrides.yml). Install
the generators if you change the configuration schema:

```sh
go install github.com/goliatone/go-generators/cmd/app-config@v0.16.1
go install github.com/goliatone/go-generators/cmd/config-getters@v0.16.1
go generate ./config
```

The convenience workflow performs configuration generation, CSS compilation,
and a local build:

```sh
./taskfile dev:run
```

That workflow also expects the `lgr` command on `PATH`. The direct
`go generate`, `npm`, and `go run` commands above do not require it.

### Tests

Run the example-module tests independently from the repository root module:

```sh
go test ./...
go test -race ./...
```

The tests cover migration/fixture idempotency, embedded and disk-overlaid
assets, template rendering, CSRF enforcement, login cookies, and startup error
redaction.

## Auth0 examples

The [`auth0`](auth0) package is composition code, not a process with a
`main` function. See the full [`Auth0 integration guide`](../docs/AUTH0.md).

### Minimal token validation

`ExampleMinimalSetup` needs:

- a migrated Bun database;
- the local `auth.Config`;
- the Auth0 tenant domain, without a URL path;
- one or more accepted API audiences;
- an optional namespaced-claim prefix; and
- a decision about whether local go-auth tokens are accepted alongside Auth0
  tokens.

In Auth0, register an API and use its identifier as the token audience. Pass
the returned authenticator or HTTP authenticator to your own router middleware;
the example does not register application routes.

### Local user synchronization

`ExampleSyncSetup` adds:

- the `user_identifiers` migration;
- an Auth0 machine-to-machine application authorized for the Auth0 Management
  API; and
- the Management API client ID and secret loaded from server-side secret
  storage.

Grant only the Management API scopes needed by the operations you call, such
as `read:users` for lookup and `update:users` for remote updates. The setup
returns a sync service and management client; invoke `SyncByID` or related
operations from your host workflow.

Relevant migrations:

```text
data/sql/migrations/20240701090000_auth0_identifiers.up.sql
data/sql/migrations/sqlite/20240701090000_auth0_identifiers.up.sql
```

For segmented migration registration, apply `auth.GetCoreMigrationsFS()`
before `auth.GetAuthExtrasMigrationsFS()`.

Current Auth0 setup references:

- <https://auth0.com/docs/get-started/auth0-overview/create-applications>
- <https://auth0.com/docs/get-started/auth0-overview/create-applications/machine-to-machine-apps>

## Supabase example

[`supabase/supabase.go`](supabase/supabase.go) demonstrates service boundaries
for a host that needs more than login:

- OIDC discovery and principal mapping;
- encrypted provider-session refresh/reconciliation hooks;
- hardened admin lifecycle and factor operations; and
- OAuth authorization details, approve, and deny operations.

`Build` requires host-owned runtime configuration and implementations for:

- provider user-token lookup;
- refresh-token validation;
- authorization CSRF verification; and
- an optional hardened HTTP client.

Provider URLs, client credentials, publishable/admin credentials,
authorization proof key, audiences, environment, registered return URLs, and
client policies must come from trusted server configuration. Do not accept
them from browser input or commit secrets to this directory.

This package does not start a server. For a runnable Supabase login and
go-admin dashboard, use the
[`supabase-dashboard`](../adapters/goadmin/cmd/supabase-dashboard/README.md)
example:

```sh
cd ../adapters/goadmin

export SUPABASE_PROJECT_URL="https://YOUR_PROJECT_REF.supabase.co"
export SUPABASE_OAUTH_CLIENT_ID="YOUR_OAUTH_CLIENT_ID"
export SUPABASE_OAUTH_CLIENT_SECRET="YOUR_OAUTH_CLIENT_SECRET"
export SUPABASE_ALLOW_INSECURE_LOOPBACK="true"
export GOAUTH_SIGNING_KEY="$(openssl rand -hex 32)"

go run ./cmd/supabase-dashboard
```

Supabase must have its OAuth 2.1 server enabled, an authorization UI, an
asymmetric JWT signing key, and a confidential OAuth application with the
exact callback documented by that example.

References:

- [`docs/SUPABASE.md`](../docs/SUPABASE.md)
- <https://supabase.com/docs/guides/auth/oauth-server/getting-started>
- <https://supabase.com/docs/guides/auth/oauth-server/oauth-flows>

## Lifecycle and claims extensions

[`extensions/extensions.go`](extensions/extensions.go) contains three pieces
that can be adopted independently:

- `NewAuditSink` converts authentication/lifecycle events into inserts against
  a host-owned `user_activity` table.
- `MultiTenantClaimsDecorator` adds a trusted tenant ID and resource roles to
  newly issued local JWTs.
- `ExampleLifecycleExtensions` shows both pieces attached to the user state
  machine and authenticator.

`ExampleLifecycleExtensions` contains nil placeholders and is illustrative; do
not call it directly. Supply real repositories, an authenticator, and a
database. The `user_activity` table is also host-owned and is not created by
the go-auth migrations, so create a schema matching the insert columns before
using the sample sink.

Claims decorators run during token issuance. Return tenant and resource-role
data only from an authoritative server-side lookup; a decorator error stops
token issuance.

## GitHub and Google social login

[`extensions/social_login.go`](extensions/social_login.go) composes local auth
with the GitHub and Google providers. It requires:

- a migrated Bun database including the `social_accounts` migration;
- a router group rooted at `/auth/social` and implementing
  `social.RouteRegistrar`;
- local `auth.Config`;
- the public base URL of the host;
- separate base64-encoded state-encryption and state-HMAC keys; and
- GitHub and Google OAuth client IDs and secrets.

Generate independent 32-byte state keys:

```sh
openssl rand -base64 32
openssl rand -base64 32
```

Register these exact callbacks with the providers, substituting your public
base URL:

```text
https://your-app.example/auth/social/github/callback
https://your-app.example/auth/social/google/callback
```

The registered routes are:

```text
GET /auth/social/providers
GET /auth/social/:provider
GET /auth/social/:provider/callback
```

Account listing, linking, and unlinking are mounted only when authenticated
browser middleware is supplied through `RegisterSecureRoutes` or
`HTTPConfig.BrowserSecurity`.

The controller always issues Secure, HttpOnly cookies. Use HTTPS for this
example, including development behind a local TLS proxy; plain HTTP will not
produce a usable browser session cookie.

Provider setup references:

- <https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app>
- <https://developers.google.com/identity/protocols/oauth2/web-server>

The default provider scopes are `user:email read:user` for GitHub and `openid
email profile` for Google. Keep secrets outside source control and use separate
OAuth applications for development and production callback URLs.

Relevant migration:

```text
data/sql/migrations/20240615090000_social_accounts.up.sql
data/sql/migrations/sqlite/20240615090000_social_accounts.up.sql
```

## Directory map

- `config/`: file configuration plus generated structs/getters.
- `data/fixtures/`: disposable local seed data.
- `views/`: server-rendered templates.
- `assets/`: Tailwind source.
- `public/`: generated and static browser assets.
- `auth0/`, `supabase/`, and `extensions/`: host integration examples.
- `*_test.go`: executable examples and regression coverage.
