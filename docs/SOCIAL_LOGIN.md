# Social Login (OAuth2)

This guide covers the social login flow implemented in `social/`, including
provider setup, routing, linking policies, migrations, and security notes.

## Overview

Supported providers in this phase:

- GitHub (OAuth2)
- Google (OIDC + OAuth2)

Social login is opt-in and does not affect existing local auth flows. The
`SocialAuthenticator` issues go-auth JWTs and can be wired alongside local
login, Auth0 validation, and the HTTP controller.

Social login account links are stored in `social_accounts`. Generic browser
SSO and Auth0 sync identity links are stored in `user_identifiers` with
`(provider, identifier)` as the canonical provider-subject key. Do not silently
split or merge identities across both tables; if a host wants social and SSO
records to resolve to the same local account, add an explicit migration or
lookup bridge and audit the linking decision.

## Requirements

- Social accounts table migration applied (see Migration Guide below).
- 32-byte state encryption key and 32-byte HMAC key (base64-encoded) for the
  OAuth state token.
- Provider client IDs, secrets, and callback URLs.

## Setup (Local + Social)

```go
import (
    "encoding/base64"

    "github.com/goliatone/go-auth"
    "github.com/goliatone/go-auth/repository"
    "github.com/goliatone/go-auth/social"
    "github.com/goliatone/go-auth/social/providers/github"
    "github.com/goliatone/go-auth/social/providers/google"
)

stateEncKey, _ := base64.StdEncoding.DecodeString(cfg.Social.StateEncryptionKey)
stateHMACKey, _ := base64.StdEncoding.DecodeString(cfg.Social.StateHMACKey)

repoManager := repository.NewRepositoryManager(bunDB)
userRepo := repoManager.Users()
socialRepo := repository.NewSocialAccountRepository(bunDB)

localProvider := auth.NewUserProvider(userRepo)
authenticator := auth.NewAuthenticator(localProvider, cfg.Auth)

socialAuth := social.NewSocialAuthenticator(
    socialRepo,
    userRepo,
    authenticator.TokenService(),
    social.SocialAuthConfig{
        DefaultRedirectURL:   "/",
        StateEncryptionKey:   stateEncKey,
        StateHMACKey:         stateHMACKey,
        AllowSignup:          true,
        AllowLinking:         true,
        RequireEmailVerified: true,
    },
    social.WithLinkingPolicy(social.PolicyEmailMatch()),
    social.WithProvider(github.New(github.Config{
        ClientID:     cfg.Social.GitHubClientID,
        ClientSecret: cfg.Social.GitHubClientSecret,
        CallbackURL:  cfg.BaseURL + "/auth/social/github/callback",
    })),
    social.WithProvider(google.New(google.Config{
        ClientID:     cfg.Social.GoogleClientID,
        ClientSecret: cfg.Social.GoogleClientSecret,
        CallbackURL:  cfg.BaseURL + "/auth/social/google/callback",
    })),
)

socialController := social.NewHTTPController(socialAuth, social.HTTPConfig{
    PathPrefix:        "/auth/social",
    SessionContextKey: cfg.Auth.GetContextKey(),
    CookieName:        cfg.Auth.GetContextKey(),
    SuccessRedirect:   "/dashboard",
    ErrorRedirect:     "/login?error=auth_failed",
    CookieSecure:      true,
    CookieHTTPOnly:    true,
    CookieSameSite:    "Lax",
})

socialController.RegisterRoutes(router.Group("/auth/social"))
```

If you need Auth0 coexistence, wire `NewMultiTokenValidator` on the
`Authenticator` and keep social login unchanged. See `docs/MIDDLEWARE.md` for
composite validation wiring.

## HTTP Routes

Routes registered by `social.HTTPController` (default path prefix
`/auth/social`):

- `GET /auth/social/providers` - list available providers
- `GET /auth/social/:provider` - begin OAuth flow
- `GET /auth/social/:provider/callback` - provider callback
- `POST /auth/social/:provider/link` - link account (authenticated)
- `DELETE /auth/social/:provider` - unlink account (authenticated)
- `GET /auth/social/accounts` - list linked accounts (authenticated)

Optional query parameters on the begin route:

- `redirect_url` sets the post-auth redirect target.
- `action` can be `login`, `signup`, or `link` (linking requires an active
  session).

## Linking Strategies

Linking is configured through a `LinkingPolicy` (see `social/linking.go`) and
executed by `PolicyLinkingStrategy`. The built-in modes are:

- `auto_create`: create a new user if none exists.
- `email_match`: link to an existing verified user with matching email.
- `explicit_only`: only link when the user explicitly starts a link flow.
- `reject_unknown`: deny if no existing user account is found.

Example policy override:

```go
social.WithLinkingPolicy(social.PolicyExplicitOnly())
```

The default strategy can also be used directly with flags:
`AllowSignup`, `AllowLinking`, `RequireEmailVerified`, and `DefaultRole`.

## Migration Guide (social_accounts)

The social login feature relies on the `social_accounts` table. The project
ships migrations for Postgres and SQLite:

- `data/sql/migrations/20240615090000_social_accounts.up.sql`
- `data/sql/migrations/20240615090000_social_accounts.down.sql`
- `data/sql/migrations/sqlite/20240615090000_social_accounts.up.sql`
- `data/sql/migrations/sqlite/20240615090000_social_accounts.down.sql`

For segmented registration use `auth.GetAuthExtrasMigrationsFS()` (register
after `auth.GetCoreMigrationsFS()`).

Notes:

- IDs use `TEXT` to align with the core `users` migration format.
- Two unique constraints are enforced: `(provider, provider_user_id)` and
  `(user_id, provider)`.
- The SQLite migration mirrors Postgres with compatible types.

Apply the migration with your existing migration tool before enabling social
login.

`social_accounts` remains OAuth/social-login state, including provider profile
and token fields used by the social package. It is not the canonical SSO
provider-subject table.

## Security Notes

- Require verified emails for auto-linking and signup (`RequireEmailVerified`).
- Avoid auto-linking privileged accounts; require explicit linking for admin or
  owner roles.
- Log link/unlink events through `ActivitySink` and inspect
  `ActivityEventSocialLogin` for audit trails.
- Use HTTPS callbacks and secure cookies in production.
- Do not expose OAuth tokens in URLs or logs; store refresh tokens encrypted at
  rest if persisted.
- GitHub tokens do not expire (revocation is manual); Google access tokens are
  short-lived and may require refresh tokens.
