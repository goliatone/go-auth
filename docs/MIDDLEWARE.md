# JWT Middleware Extensions

go-auth’s middleware surface provides two capabilities that make it easier to power admin transports: automatic actor context enrichment and token validation listeners. Both features plug into `jwtware.Config`, so apps can enable them without changing existing routing code.

## Actor Context Enrichment

`RouteAuthenticator` includes a default `ContextEnricher` that persists a normalized `auth.ActorContext` inside the request context immediately after JWT validation. The payload captures the fields guard adapters and scope checks need without re-parsing headers:

| Field | Source |
| --- | --- |
| `ActorID` / `Subject` | `claims.UserID()` / `claims.Subject()` |
| `Role` | `claims.Role()` |
| `ResourceRoles` | `claims.Resources` (if present) |
| `TenantID` | `claims.Metadata["tenant_id"|"tenant"|"default_tenant"|"default_tenant_id"]` |
| `OrganizationID` | `claims.Metadata["organization_id"|"org_id"|"org"]` |
| `ImpersonatorID` / `IsImpersonated` | `claims.Metadata["impersonator_id"|"impersonation_actor_id"]` or `claims.Metadata["impersonated"] == true` |
| `Metadata` | defensive clone of `claims.Metadata` |

Helpers make the payload easy to consume from either standard or router contexts:

```go
actor, ok := auth.ActorFromContext(ctx)              // stdlib context
actor, ok := auth.ActorFromRouterContext(routerCtx) // go-router context
```

Claims that already contain tenant/organization metadata are picked up automatically because the enricher reads the union of supported keys. Downstream services can keep decorating claims through `ClaimsDecorator`, and `ActorContext` remains consistent. Guard adapters can also rely on `ActorContextFromClaims` in tests to generate fixtures that match runtime behavior.

If you build `jwtware.Config` directly (instead of using `RouteAuthenticator`), reuse the same adapter:

```go
jwtMiddleware := jwtware.New(jwtware.Config{
    TokenValidator: tokenService,
    ContextKey: "user",
    ContextEnricher: auth.ContextEnricherAdapter,
})
```

## Token Validation Listeners

Set `jwtware.Config.ValidationListeners` (or use `RouteAuthenticator.WithValidationListeners`) to register callbacks that fire immediately after token validation succeeds and before authorization checks run. Listeners receive the active `router.Context` plus the validated `AuthClaims`, enabling side effects such as:

- publishing “session validated” activity events;
- triggering schema cache refreshes for go-admin/go-cms;
- pushing impersonation audits when `ActorContext.IsImpersonated` is true.

Listener signature:

```go
type ValidationListener func(ctx router.Context, claims jwtware.AuthClaims) error
```

Return `nil` to continue the request, or an `error` to short-circuit through the configured `ErrorHandler`. Example wiring alongside the HTTP authenticator:

```go
actorAudit := func(ctx router.Context, claims jwtware.AuthClaims) error {
    stdCtx := auth.WithClaimsContext(ctx.Context(), claims.(auth.AuthClaims))
    if actor, ok := auth.ActorFromContext(stdCtx); ok {
        activitySink.Emit(ctx.Context(), auth.ActivityEvent{
            EventType: auth.ActivityEventLoginSuccess,
            Actor:     auth.ActorRef{ID: actor.ActorID, Type: actor.Role},
        })
    }
    return nil
}

httpAuth, _ := auth.NewHTTPAuthenticator(appAuther, appConfig)
httpAuth.WithValidationListeners(actorAudit)
```

Services that construct `jwtware.Config` directly can provide the listener slice on the config struct. Because listeners execute before request-scoped guards, they are the right hook for broadcasting validated actor data to schema watchers, cache layers, or audit sinks.

If you want a tiny helper for wiring listeners without mutating slices yourself, use:

```go
cfg := jwtware.Config{TokenValidator: tokenService}
auth.RegisterValidationListeners(&cfg, actorAudit)
```

## Composite Token Validation (Auth0 + Social)

If your app accepts both Auth0-issued JWTs and go-auth tokens (including social
login), use `NewMultiTokenValidator` to try multiple validators in order. The
composite only falls through on `ErrTokenMalformed` and returns the first
successful claims.

```go
auth0Validator, _ := auth0.NewTokenValidator(auth0.Config{
    Domain:   cfg.Auth0.Domain,
    Audience: cfg.Auth0.Audience,
})

auther := auth.NewAuthenticator(localProvider, cfg.Auth)
socialAuth := social.NewSocialAuthenticator(
    socialRepo,
    userRepo,
    auther.TokenService(),
    socialConfig,
    social.WithProvider(githubProvider),
    social.WithProvider(googleProvider),
)

composite := auth.NewMultiTokenValidator(auth0Validator, auther.TokenService())
auther = auther.WithTokenValidator(composite)

httpAuth, _ := auth.NewHTTPAuthenticator(auther, cfg.Auth)
socialController := social.NewHTTPController(socialAuth, httpConfig)
socialController.RegisterRoutes(router.Group(\"/auth/social\"))
```

Make sure the Auth0 validator normalizes non-Auth0 tokens to `ErrTokenMalformed`
so the composite can fall back to the go-auth validator.

## Putting It Together

Typical workflow for go-users/go-admin transports:

1. Decorate JWTs with tenant/org metadata through `ClaimsDecorator`.
2. Serve protected routes via `RouteAuthenticator` so each request receives an `ActorContext`.
3. Register validation listeners that emit audits, refresh admin schemas, or track impersonation.
4. Inside go-crud controllers or guard adapters, call `auth.ActorFromRouterContext(ctx)` to retrieve the normalized payload and feed it into scope guards.

This approach keeps actor extraction centralized in go-auth while giving downstream services deterministic inputs for policy enforcement, auditing, and schema distribution.
