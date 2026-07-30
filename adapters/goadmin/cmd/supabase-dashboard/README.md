# Supabase go-admin dashboard

This executable is a browser-first Supabase integration example:

- Supabase is the OIDC identity provider.
- go-auth validates the callback, links a local identity, and issues the local
  admin session cookie.
- go-router serves the HTTP application.
- go-admin owns the protected SSR dashboard at `/admin/dashboard`.
- SQLite stores local users and immutable Supabase subject bindings. Provider
  access, refresh, and ID tokens are not persisted.

## 1. Configure Supabase

In the Supabase dashboard:

1. Open **Authentication > OAuth Server** and enable the OAuth 2.1 server.
2. Configure a working authorization UI. Supabase redirects the user there to
   authenticate and approve the request; this example is the OAuth client and
   does not replace that UI.
3. Use an asymmetric JWT signing key (ES256 or RS256). OIDC ID tokens cannot
   use the legacy HS256 project secret.
4. Open **Authentication > OAuth Apps**, add a confidential client, and set:
   - Redirect URI:
     `http://127.0.0.1:8081/admin/sso/callback/supabase`
   - Token endpoint authentication:
     `client_secret_basic`
5. Copy the client ID and the one-time client secret.

Supabase setup reference:

- <https://supabase.com/docs/guides/auth/oauth-server/getting-started>
- <https://supabase.com/docs/guides/auth/oauth-server/oauth-flows>

## 2. Run the dashboard

From `adapters/goadmin`:

```sh
export SUPABASE_PROJECT_URL="https://YOUR_PROJECT_REF.supabase.co"
export SUPABASE_OAUTH_CLIENT_ID="YOUR_OAUTH_CLIENT_ID"
export SUPABASE_OAUTH_CLIENT_SECRET="YOUR_OAUTH_CLIENT_SECRET"
export SUPABASE_ALLOW_INSECURE_LOOPBACK="true"
export GOAUTH_SIGNING_KEY="$(openssl rand -hex 32)"

go run ./cmd/supabase-dashboard
```

Then open <http://127.0.0.1:8081/admin/login> and choose Supabase.

`SUPABASE_ALLOW_INSECURE_LOOPBACK=true` is required for the local HTTP callback.
It permits HTTP only on loopback hosts; the Supabase project endpoints remain
HTTPS.

This development host grants dashboard-view permission to any user who
successfully authenticates through the configured OAuth application. Add your
normal local authorization policy before using this composition outside an
isolated integration environment.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SUPABASE_PROJECT_URL` | required | Project origin, such as `https://ref.supabase.co` |
| `SUPABASE_OAUTH_CLIENT_ID` | required | Registered OAuth application client ID |
| `SUPABASE_OAUTH_CLIENT_SECRET` | required for confidential clients | OAuth client secret |
| `SUPABASE_OAUTH_CLIENT_AUTH_METHOD` | `client_secret_basic` | `none`, `client_secret_basic`, or `client_secret_post` |
| `SUPABASE_ID_TOKEN_AUDIENCE` | client ID | Comma-separated accepted ID-token audiences |
| `SUPABASE_ACCESS_TOKEN_AUDIENCE` | `authenticated` | Comma-separated accepted access-token audiences |
| `SUPABASE_ALLOWED_ALGORITHMS` | `ES256,RS256` | Accepted asymmetric signing algorithms |
| `SUPABASE_ALLOW_INSECURE_LOOPBACK` | `false` | Explicitly allow loopback HTTP endpoints/callbacks |
| `GOAUTH_SIGNING_KEY` | required | At least 32 bytes; signs local admin JWTs |
| `APP_URL` | `http://127.0.0.1:8081` | Public origin used to build the exact callback |
| `SERVER_ADDR` | `127.0.0.1:8081` | Listen address |
| `DATABASE_DSN` | local `supabase-dashboard.db` | SQLite DSN for local users and identifiers |

If a Supabase Custom Access Token Hook changes `aud`, set
`SUPABASE_ACCESS_TOKEN_AUDIENCE` to the exact validated value.

## What to inspect

- `/admin/sso/providers` returns the secret-free provider list.
- `/admin/sso/login/supabase` begins the PKCE authorization-code flow.
- `/admin/sso/callback/supabase` validates and completes the callback.
- `/admin/dashboard` shows linked Supabase identities and integration actions.
- `supabase-dashboard.db` contains local users and `user_identifiers`; it does
  not contain provider tokens.

Provider-session mode is intentionally a separate next step. It requires
encrypted token storage, locking, refresh coordination, and local revocation;
the local-token example does not fake those guarantees.
