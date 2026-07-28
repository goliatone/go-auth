# OIDC SSO

Generic browser SSO lives in `provider/oidc`. The zero-value callback mode
preserves the existing local go-auth JWT behavior. Hardened callers can opt
into an allowlisted principal-aware local JWT or an atomic server-side provider
session handoff. Provider tokens never cross the browser result boundary.

## Setup Checklist

- Configure issuer or discovery URL, client ID, redirect URL, scopes, audience,
  and allowed signing algorithms for each provider.
- Wrap client credentials with `auth.NewSecret` and explicitly select
  `none`, `client_secret_basic`, or `client_secret_post` for hardened modes.
- Register the callback URL with the provider exactly as configured in
  `ProviderConfig.RedirectURL`.
- Keep `openid` in scopes; `profile`, `email`, and provider-specific scopes
  such as `groups` are optional but commonly needed for mapping.
- Configure safe post-login redirects with same-origin relative paths by
  default, or explicit allowed origins when absolute redirects are required.
- Use HTTPS for issuer, discovery, provider, and callback endpoints. Local
  development may set `AllowInsecureHTTP`, but only loopback HTTP is accepted.
- Use `auth.NewMultiTokenValidator(oidcValidator, auther.TokenService())` when
  APIs must accept both external IdP access tokens and local go-auth JWTs.

## Callback Modes

`oidc.LocalTokenMode` is the zero value. With no `LocalClaimPolicy`, it uses the
existing `BrowserTokenIssuer` unchanged. To add normalized provider/session
claims to a local JWT, configure `PrincipalTokenIssuer` plus an explicit
`LocalClaimPolicy`; raw tokens, permission lists, and arbitrary provider claims
are never eligible. The browser resolves the policy first, so the enriched
issuer receives only the resulting normalized claim map rather than the raw
principal or provider resource roles.

`oidc.ProviderSessionMode` requires `ProviderSessionHandoff` and forbids a local
token issuer. It also requires an identity linker advertising
`IdentifierBindingImmutableRequired` or stronger. Configure the built-in
linker with that binding mode; signup additionally requires the transactional
create-and-bind capability. `IdentifierBindingLegacyCompatible` is only for
existing local-token integrations whose custom stores still depend on mutable
`Upsert`.

The handoff receives `auth.AuthenticatedPrincipal` plus an opaque
`auth.ProviderTokenSet` after identity linking. It must atomically persist or
discard the session and return `ProviderSessionHandoffResult`, containing an
opaque host-session secret plus the non-secret local session ID. The callback
binds that ID to the final principal before returning. JSON serialization in
this mode is a strict safe view containing only provider key, validated
redirect target, and typed allowlisted audit context; identity, claims,
principal data, roles, metadata, tokens, and the host-session secret are
omitted.

HTTP adapters should use `AuthorizationResponse.HTTPRedirectURL()` and
`BrowserSessionResult.SessionSecret()`. The exported `State`, `Nonce`, and
`CodeVerifier` fields remain readable for one compatibility release, but are
deprecated and omitted/redacted from serialization, formatting, and logging.
Custom token exchangers may still populate the deprecated string token fields
for one release; new code should populate `AccessTokenValue`, `IDTokenValue`,
and `RefreshTokenValue`. Conflicting legacy and secret values fail closed.

## Confidential Clients and Supabase

```go
provider := oidc.ProviderConfig{
    Key:                     "supabase",
    Issuer:                  "https://project.supabase.co/auth/v1",
    ClientID:                "server-client-id",
    ClientSecretValue:       auth.NewSecret(secretManagerValue),
    TokenEndpointAuthMethod: oidc.TokenEndpointAuthClientSecretBasic,
    RedirectURL:             "https://backoffice.example.com/sso/callback/supabase",
    AllowedAlgorithms:       []string{"ES256"},
}
```

Discovery metadata is authoritative. If
`token_endpoint_auth_methods_supported` is omitted, explicit hardened
configuration defaults to `client_secret_basic` per RFC 8414. The legacy empty
method retains the historical Post-with-secret/None-without-secret inference
only in legacy local-token mode.

## Validation and Limits

ID tokens validate exact trusted audiences, `azp`, and `at_hash` when present.
UserInfo is profile enrichment only and its `sub` must match the ID-token
subject. Access-token claims affect a principal only when
`RequireAccessTokenClaims` is enabled and the JWT validates independently.

RS256/384/512, PS256/384/512, and ES256 with P-256 are supported. Default
limits are 1 MiB for discovery/JWKS/UserInfo, 256 KiB for token responses,
64 KiB per encoded token, 100 JWKS keys, 8 KiB callback code/redirect, 1 KiB
state, 10,000 pending in-memory states, and a 10-second provider-request
deadline. Override them with `ProviderConfig.Limits`, `RequestTimeout`, and
`BrowserAuthenticatorConfig.StateCapacity`.

Discovery, JWKS, token, and UserInfo clients never follow redirects. Unknown
key IDs share a coalesced JWKS refresh and a 30-second default cooldown,
configurable with `JWKSRefreshCooldown`. RSA keys must be between 2048 and
16384 bits with a safe odd exponent; P-256 keys use checked encoded-point
parsing.

## Delivery Order

Release the root `go-auth` module containing the additive contracts first.
Then update and release nested adapters without local `replace` directives.
Live Supabase conformance, exact environment URLs, production secrets, and
cross-project RLS trust remain a separate environment-gated validation step;
they do not change provider-neutral callback behavior.

## Identity Mapping

Lookup order:

1. `user_identifiers` by `(provider, subject)`.
2. Verified-email fallback only when explicitly enabled by host policy.
3. New local user creation only when signup is enabled.

Unverified-email auto-linking is rejected by default. Social OAuth mappings in
`social_accounts` are separate and should only participate through an explicit
host migration or lookup bridge.

Provider-subject bindings are immutable in hardened modes. Repeating a bind to the same local
user is idempotent; binding the same `(provider, subject)` to another user
returns `auth.ErrIdentifierConflict`. Repository-backed OIDC signup creates the
user and binding in one transaction. A custom store selected for hardened
signup must implement `TransactionalIdentifierStore`; the compensating
create/delete path remains available only in legacy-compatible mode.

## Provider-session database migration

Apply the additive provider-session migrations through `20260727160000` before
starting hardened instances. They add lifecycle fences, the durable lifecycle
operation ledger, the remote-revocation queue, and typed reason fingerprints.
Deploy database changes before binaries that require them. Roll back binaries
first; down migrations remove durable state and must not run while lifecycle or
revocation workers are active. Existing local-token-only deployments do not
need these tables.

Provider-session manager construction requires an explicit `development`,
`test`, `production`, or `hardened` deployment class. Lifecycle coordinator
construction likewise requires an explicitly supplied operation store.
Hardened Supabase mutations accept permits only from a Postgres-backed store;
in-memory or SQLite operation stores remain explicit local compatibility
choices.

## Troubleshooting

Discovery fails:
Check issuer spelling, HTTPS reachability, and that discovery returns
`issuer`, `jwks_uri`, `authorization_endpoint`, and `token_endpoint`. If the
issuer in discovery does not exactly match the configured issuer after trailing
slash normalization, validation fails.

Unknown signing key or key rotation failures:
Confirm the provider publishes the new key in JWKS before issuing tokens with
that `kid`. The validator refreshes JWKS on unknown keys, but a token remains
invalid if the refreshed set still lacks the key.

Callback URL mismatch:
The IdP redirect URI must match `ProviderConfig.RedirectURL`. A mismatch often
appears as a provider-side redirect error before go-auth receives the callback.

State or nonce failures:
Use the same state store for begin-login and callback, preserve browser cookies
between redirects, and avoid replaying callback URLs. Nonce mismatch means the
`id_token` is not tied to the stored browser login attempt.

ID token validation failures:
ID tokens must include issuer, audience, expiration, issued-at, signature, and
nonce. Access-token validation may accept provider API audiences, but browser
ID-token validation defaults audience checks to `ProviderConfig.ClientID`.

Unsafe redirect rejection:
Use relative paths such as `/admin`. Absolute redirect targets must match an
explicit allowed origin. Backslashes, protocol-relative URLs, and external
origins are rejected.

Algorithm or key-use rejection:
Set `AllowedAlgorithms` to the provider's expected signing algorithms, usually
`RS256` or `ES256`. The validator supports RSA/PS algorithms and ES256/P-256.
`none`, explicitly configured unsupported algorithms, and discovery metadata
with no supported algorithm are rejected during setup. JWKs with `use` or
`key_ops` that do not allow signing are not accepted for token verification.

Unverified email link rejection:
Email fallback is opt-in and should require verified email. If a user cannot
link by email, prefer linking by provider subject or enable verified-email
fallback deliberately.

Manual link or unlink failures:
Manual account linking requires a host-supplied proof verifier before the
adapter calls the linker. Manual unlinking removes the `(provider, subject)`
mapping for the authenticated user through `IdentifierStore.Delete`.

Provider list secrets:
Only expose display data: provider key, label, login URL, icon metadata, and
disabled reason. Do not return client secrets, tokens, discovery documents, or
raw provider configuration to the browser.

Permission resolver denial:
Custom admin actions are denied unless they are returned by
`GoAuthAuthorizerConfig.ResolvePermissions`. Map IdP `permissions`, `roles`,
or `groups` into canonical admin permission strings, then compose them with
host-local policy. Resolver errors are deny decisions.
