# Supabase provider

`provider/supabase` adds Supabase-specific behavior over hardened generic OIDC.
It keeps passwords, MFA challenges, recovery, token issuance, business roles,
application assignments, and consent presentation in their owning systems.

## Runtime boundaries

- Generic OIDC owns discovery, PKCE, state, nonce, exchange, issuer/audience
  validation, signatures, and JWKS.
- Provider sessions own encrypted token custody, refresh locking, rotation
  ambiguity, persistence, opaque cookies, and local revocation.
- Supabase owns bounded remote refresh, sign-out, identity, factor, and OAuth
  decision calls.
- `LifecycleCoordinator` owns local-first security ordering and calls
  freshness invalidation with a stable operation ID.
- Backoffice owns permission checks, public login/consent presentation, CSRF,
  application registry, reconciliation jobs, and durable audit storage.

## Required configuration

Load these values through host configuration and secret management:

| Input | Purpose | Required owner |
|---|---|---|
| Project URL, issuer, discovery URL | Exact identity project trust boundary | Identity provider owner |
| OAuth client ID/secret and auth method | Backoffice confidential OIDC client | OAuth client owner |
| Exact callback and authorization UI URLs | Login and public consent entry | Backoffice owner |
| ID/access audiences and RS256/ES256 algorithms | Token trust policy | Identity/security owner |
| Publishable key | User-bound recovery and authorization calls | Identity provider owner |
| Admin credential | Narrow server-only lifecycle/factor calls | Privileged credential owner |
| Authorization proof key | Shared 32–128 byte HMAC key for details/decision continuity | Backoffice secret owner |
| Optional management credential | Deployment/control-plane checks only | Platform owner |
| Exact return URLs and OAuth client policies | Recovery and client redirect policy | Application registry owner |
| Environment and API versions | Deployment isolation and provider contract | Release owner |
| Explicit provider-session deployment class | Provider-session operations gate only | Release owner |

Admin, publishable, OAuth client, and management values must be distinct.
Construction fails on insecure production URLs, duplicate values, mixed
credentials, weak algorithms, unknown scopes, or open return policies. HTTP is
available only for explicit loopback development.

Local-token OIDC, principal mapping, and ordinary Supabase API clients do not
require provider-session deployment policy. When provider sessions are
enabled, set `Config.ProviderSessionDeployment` and call
`Config.ProviderSessionManagerConfig` while constructing the manager, or set
`ProviderSessionManagerConfig.Deployment` directly. Use `development` or
`test` only for those deployment classes; use `production` or `hardened` for
any live service regardless of free-form environment aliases such as `live`,
`prd`, or `production-us`. Production/hardened manager construction requires a
complete `ProviderSessionOperationsConfig` whose environment and session
lifetimes exactly match the runtime binding.

## Sign-in and provider sessions

Call `Config.OIDCConfig()` and use `Config.PrincipalMapper(...)` as the OIDC
principal mapper. Use provider-session mode and wire `SessionClient` as the
manager's refresher, reconciler, and remote revocation hook. The session
manager—not Supabase—owns refresh coordination and token persistence.

Refresh validates the new access token and binds a returned ID token to it.
Subject, provider session, issuer, client, audiences, assurance, methods,
authentication time, issue time, expiry, the `authenticated` user role, and
the configured scope allowlist must remain valid. Supabase cannot return
rotated token material after an ambiguous refresh, so reconciliation is
explicitly `unknown` and the session manager requires fresh authentication.

Current and all-session sign-out are supported. Named remote session sign-out
is typed `unsupported`. Sign-out revokes refresh/session state, but an issued
access JWT can remain valid until its recorded expiry; privileged actions must
also enforce account and authorization freshness. Logout transport requires a
validated access context matching the configured issuer/client/audience and,
for the provider-session hook, the stored subject and provider session ID.

## Lifecycle and factors

Every call requires `AuthorizedOperationContext` containing a stable operation
ID, exact action, host permission, actor, target, reason, environment, and
request correlation. Invalid or mismatched proof fails before transport.

Use a durable `LifecycleCoordinator` and `NewHardenedAdminClient` for
suspension, activation, and factor removal. The closed action policy derives
the lifecycle fence and local session effect; callers cannot weaken those
effects with request booleans. Local invalidation advances the lifecycle fence
and makes sessions unusable before the coordinator mints a bound execution
permit and invokes Supabase. Permits are single-use, checked against the live
ledger revision/attempt/lease immediately before mutation transport, and
invalidated when dispatch returns. Missing, replayed, forged, stale,
non-durable, or cross-operation permits fail before transport.

The Bun `LifecycleOperationStore` is authoritative across replicas and
restarts. It persists phase progress, compare-and-swap revisions, bounded
leases, fingerprints, and ambiguous remote delivery. In-memory operation
storage must be selected explicitly and is compatibility-only; a nil store is
a construction error, and hardened Supabase coordination requires a Postgres
store. Configure a reconciliation worker to call `ClaimPending`, establish the
provider outcome without replaying the mutation, and pass the live claim plus
the original typed request to `ReconcileLifecycleOperation`. The coordinator
checks the claim lease and canonical fingerprint, persists the authoritative
outcome, and resumes freshness/completion. `ActivitySink` remains best-effort
audit telemetry and is not a consistency mechanism.

Factor removal requires `Operation.Target.ObjectID` to match `FactorID`.
Supabase re-reads the authoritative factor list immediately before deletion;
caller state/count fields are optional concurrency expectations, never security
inputs. Local invalidation is conservative for every factor-removal attempt so
a stale hint cannot bypass verified-factor ordering. Last-verified-factor
removal is denied unless the host explicitly authorizes it. Factor ID, known
state, remaining-factor expectation, and last-factor authorization are included
in the canonical operation fingerprint, so changing one while reusing an
operation ID conflicts.

## Authorization UI

The public Backoffice entry stores only a bounded `AuthorizationContinuation`
through central login. Details, approve, and deny require:

- the same validated central Supabase provider user/session;
- an internal `UserTokenProvider` target/capability;
- a registered client and allowed scope set;
- the server-held HMAC proof returned by details retrieval;
- host-verified CSRF bound to action, client, requested/granted scopes, provider
  subject/session, environment, and details expiry; and
- an exact registered redirect returned by Supabase.

These calls use the publishable key plus the current provider user token.
Admin, management, and Backoffice-local credentials cannot substitute. The
decision redirect is redacted from formatting/logging and omitted from JSON;
browser code must explicitly call `HTTPRedirectURL()`.

## Errors, retries, and audit

Responses are size-bounded, redirects are rejected, request metadata is
validated, and error bodies are never copied into public errors. Reads retry
at most three times with bounded backoff. A mutation is retryable only when its
method contract is proven safe and it carries an idempotency key. Unsafe
timeouts and `5xx` responses are `pending`/ambiguous and are not replayed
blindly. Successful responses that cannot be read or decoded after an unsafe
mutation are also ambiguous because the provider may already have committed.

Audit records may include actor, target, action, result, reason, request ID,
provider session correlation, environment, and residual expiry. Configure
`WithActivitySink` on the Supabase client and optionally
`WithActivityErrorHandler` to surface best-effort delivery failure. Every
free-form value is one-way fingerprinted before the event is constructed;
tokens, authorization codes, cookies, credentials, and opaque secrets never
enter event or normalized audit data.

Provider-session revocation is local-first. Configure a bounded scheduler to
call `RetryRemoteRevocations`; repository claims use leases, attempt limits,
and exponential backoff. The default policy caps remote work at 10 attempts,
24-hour backoff, and the configured encrypted-token retention window.
The repository clock owns claim eligibility, lease expiry, retention, and
backoff scheduling. Each provider attempt receives a context bounded by the
claimed lease, and completion must present the exact live lease owner and
deadline.
Terminal completion or retention expiry deletes ciphertext while preserving
the session tombstone. Security lifecycle transitions enqueue every changed
session in this queue within the same transaction as local revocation. Session
reasons are typed codes plus validated one-way detail fingerprints—legacy or
malformed encoded strings are normalized immediately at parsing, persistence,
load, and activity boundaries.

Apply and verify migrations through `20260727170000` in both the aggregate and
`auth_extras` tracks. Stop lifecycle/revocation workers before rollback, roll
back application binaries first, and do not remove ledger/queue tables while
pending work exists. Cleanup and retry schedules require named owners; the
library does not start background workers.

Emergency operations must authorize through
`EmergencyAccessPolicy.AuthorizeGrant`, an authoritative versioned grant
resolver, and an isolated credential verifier. Caller-constructed grants are
accepted only when `AllowLegacyAuthorize` is explicitly enabled and must not be
used by hardened deployments. Revoke authoritative grants with
`RevokeIssuedGrant(grantID, grantVersion, ...)`; the deprecated logical-ID
`Revoke` method is compatibility-only and fails closed for authoritative
policies.

## Deployment gates

Before production enablement, run live conformance for exact endpoints, client
authentication, API versions, public-signup policy, OAuth server maturity,
refresh/logout behavior, factor side effects, and key rotation. Separately
prove the selected cross-project trust/RLS branch. A failed RLS trust branch
does not enable service-role fallback or change the provider adapter boundary.
The live Supabase/RLS stream remains blocked on named environment owners and
actual external evidence; deterministic library tests do not claim that proof.
