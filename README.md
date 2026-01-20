# go-auth

A Go authentication library providing JWT based authentication, password management, and role based access control with support for resource level permissions.

## Features

- JWT token generation and validation with structured claims
- Password hashing and verification using bcrypt
- User registration and login with email validation
- Password reset flow with email verification
- Role based access control (RBAC) with hierarchical permissions
- Resource level permissions for fine grained access control
- HTTP middleware for route protection
- Built in authentication controllers for web applications
- Database persistence layer using Bun ORM
- OAuth2 social login (GitHub, Google) with account linking
- Customizable identity providers and role providers

## Installation

```bash
go get github.com/goliatone/go-auth
```

## Quick Start

### Basic Authentication Setup

```go
package main

import (
    "context"
    "github.com/goliatone/go-auth"
    repo "github.com/goliatone/go-auth/repository"
)

func main() {
    // Create repository manager
    repoManager := repo.NewRepositoryManager(bunDB)

    // Create user provider
    userProvider := auth.NewUserProvider(repoManager.Users())

    // Create authenticator with basic configuration
    config := &AuthConfig{
        SigningKey:      "your-secret-key",
        TokenExpiration: 24, // hours
        Issuer:         "your-app",
        Audience:       []string{"your-audience"},
    }

    authenticator := auth.NewAuthenticator(userProvider, config)

    // Login user
    token, err := authenticator.Login(context.Background(), "user@example.com", "password")
    if err != nil {
        log.Fatal(err)
    }

    // Validate token and get session
    session, err := authenticator.SessionFromToken(token)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("User ID: %s\n", session.GetUserID())
}
```

### Enhanced Resource Level Permissions

```go
// Implement ResourceRoleProvider for fine-grained permissions
type CustomResourceRoleProvider struct {
    repo auth.RepositoryManager
}

func (p *CustomResourceRoleProvider) FindResourceRoles(ctx context.Context, identity auth.Identity) (map[string]string, error) {
    resourceRoles := make(map[string]string)

    switch identity.Role() {
    case "admin":
        resourceRoles["admin:dashboard"] = "owner"
        resourceRoles["project:default"] = "admin"
    case "user":
        resourceRoles["project:default"] = "member"
    }

    return resourceRoles, nil
}

// Use enhanced authenticator
authenticator = authenticator.WithResourceRoleProvider(&CustomResourceRoleProvider{repo: repoManager})

// Generated tokens will include resource-specific permissions
token, err := authenticator.Login(ctx, "admin@example.com", "password")
```

### HTTP Integration

```go
// Create HTTP authenticator for web applications
httpAuth, err := auth.NewHTTPAuthenticator(authenticator, config)
if err != nil {
    log.Fatal(err)
}

// Register authentication routes (login, register, password reset)
auth.RegisterAuthRoutes(router.Group("/auth"),
    auth.WithControllerLogger(logger),
    func(ac *auth.AuthController) *auth.AuthController {
        ac.Auther = httpAuth
        ac.Repo = repoManager
        return ac
    })

// Protect routes with middleware
protected := httpAuth.ProtectedRoute(config, errorHandler)
router.Get("/profile", profileHandler, protected)
```

**Success handler contract (jwt middleware)**  
The JWT middleware now invokes a `SuccessHandler` with the signature `func(ctx router.Context, next router.HandlerFunc) error`. The default simply calls `next(ctx)`. If you override it, you are responsible for deciding whether to call `next` (run the protected handler) or short-circuit (e.g., redirect). Example:

```go
protected := httpAuth.ProtectedRoute(config, errorHandler)

// Custom success hook that adds logging, then runs the handler
wrapped := func(ctx router.Context) error {
    return protected(func(c router.Context) error {
        log.Println("auth ok for", c.Path())
        return profileHandler(c) // or c.Next() if chaining
    })(ctx)
}

router.Get("/profile", profileHandler, wrapped)
```

### Social Login (OAuth2)

```go
import (
    "encoding/base64"

    "github.com/goliatone/go-auth/social"
    "github.com/goliatone/go-auth/social/providers/github"
    "github.com/goliatone/go-auth/social/providers/google"
    repo "github.com/goliatone/go-auth/repository"
)

stateEncKey, _ := base64.StdEncoding.DecodeString(cfg.Social.StateEncryptionKey)
stateHMACKey, _ := base64.StdEncoding.DecodeString(cfg.Social.StateHMACKey)

socialRepo := repo.NewSocialAccountRepository(bunDB)

socialAuth := social.NewSocialAuthenticator(
    socialRepo,
    repoManager.Users(),
    authenticator.TokenService(),
    social.SocialAuthConfig{
        DefaultRedirectURL:   "/",
        StateEncryptionKey:   stateEncKey,
        StateHMACKey:         stateHMACKey,
        AllowSignup:          true,
        AllowLinking:         true,
        RequireEmailVerified: true,
    },
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

Routes registered by the controller:

- `GET /auth/social/providers`
- `GET /auth/social/:provider`
- `GET /auth/social/:provider/callback`
- `POST /auth/social/:provider/link`
- `DELETE /auth/social/:provider`
- `GET /auth/social/accounts`

See `docs/SOCIAL_LOGIN.md` for linking policies, migration guidance, and security notes.
Example wiring lives in `examples/extensions/social_login.go`.

### Auth0 Integration (Optional)

Auth0 support is opt-in and uses `provider/auth0` for JWT validation and claims
mapping. For Auth0 + local tokens, use `NewMultiTokenValidator` to accept both.

```go
import "github.com/goliatone/go-auth/provider/auth0"

auth0Validator, err := auth0.NewTokenValidator(auth0.Config{
    Domain:   "your-tenant.auth0.com",
    Audience: []string{"https://api.yourapp.com"},
})
if err != nil {
    return err
}

authenticator := auth.NewAuthenticator(userProvider, cfg.Auth)

// Accept Auth0 tokens only.
authenticator = authenticator.WithTokenValidator(auth0Validator)

// Or accept Auth0 + local go-auth tokens.
composite := auth.NewMultiTokenValidator(auth0Validator, authenticator.TokenService())
authenticator = authenticator.WithTokenValidator(composite)
```

For sync (local mirroring), use `provider/auth0/sync` with an IdentifierStore.
See `docs/AUTH0.md` and `examples/auth0/` for full examples.

Auth0 validation errors normalize to `ErrTokenExpired` / `ErrTokenMalformed`
with `provider=auth0` metadata. Use `HasUserUUID(session)` before calling
`Session.GetUserUUID` because Auth0 `sub` values are not UUIDs.

### Session with Resource Permissions

```go
// Check permissions in handlers
func profileHandler(c router.Context) error {
    session, err := auth.GetRouterSession(c, "auth")
    if err != nil {
        return err
    }

    // Enhanced session with resource-level permissions
    if roleCapableSession, ok := session.(auth.RoleCapableSession); ok {
        canEditSettings := roleCapableSession.CanEdit("admin:settings")
        canDeleteUsers := roleCapableSession.CanDelete("admin:users")
        hasAdminRole := roleCapableSession.HasRole("admin")
        isAtLeastMember := roleCapableSession.IsAtLeast("member")

        // Use permissions for authorization logic
    }

    return c.JSON(map[string]any{
        "user_id": session.GetUserID(),
        "data": session.GetData(),
    })
}
```

### CSRF Protection

`go-auth` ships with a CSRF middleware that plugs into `go-router` and the template helper stack.

**Stateless (default)**

```go
import (
    csrf "github.com/goliatone/go-auth/middleware/csrf"
    "github.com/goliatone/go-router"
)

func main() {
    app := router.New()

    // HMAC-signed tokens; no backing store required
    app.Use(csrf.New(csrf.Config{
        SecureKey: []byte("your-32-byte-secret"),
    }))

    app.Post("/submit", func(ctx router.Context) error {
        // Token checked automatically
        return ctx.SendStatus(router.StatusNoContent)
    })

    app.Listen(":8080")
}
```

**Stateful (storage backed)**

```go
type redisStorage struct{ client *redis.Client }

func (r *redisStorage) Get(key string) (string, error) {
    return r.client.Get(context.Background(), key).Result()
}

// Set/Delete omitted for brevity

app.Use(csrf.New(csrf.Config{
    Storage:    &redisStorage{client: redisClient},
    Expiration: 24 * time.Hour,
}))
```

**Templates**

```go
// Inside your handler
viewCtx := auth.MergeTemplateData(ctx, router.ViewContext{
    "title": "Secure form",
})

// MergeTemplateData copies the latest request scoped helpers so csrf_field,
// csrf_meta, etc. always render the token minted by the middleware.
return ctx.Render("form", viewCtx)
```

> `csrf_field`, `csrf_token`, and `csrf_meta` are now lazily evaluated helpers. When you register `auth.TemplateHelpers()` globally, the template engine resolves the current request’s CSRF token automatically—no need to clone helper maps on every render (though `MergeTemplateData` remains useful when you want a concrete snapshot).

```html
<form method="post">
    {{ csrf_field }}
    <!-- other fields -->
</form>

<script>
    const token = "{{ csrf_token }}";
    const header = "{{ csrf_header_name }}";
    fetch("/submit", {
        method: "POST",
        headers: { [header]: token },
    });
</script>
```

```html
<!-- Layout head section -->
{{ csrf_meta }}
<meta name="another-example" content="value">
```

See `middleware/csrf/README.md` for more examples and configuration options (custom token lookup, skipping routes, etc.).

**AJAX/SPA bootstrap endpoint**

For clients that need to refresh tokens via XHR (e.g., SPAs), register the helper route:

```go
import csrf "github.com/goliatone/go-auth/middleware/csrf"

csrf.RegisterRoutes(app.Router())
```

The handler returns JSON:

```json
{
  "token": "...",
  "field_name": "_token",
  "header_name": "X-CSRF-Token"
}
```

Responses include `Cache-Control: no-store`, so clients fetch fresh tokens as needed. Call this endpoint whenever a token expires or before issuing state-changing requests in a long-lived SPA session.

## Lifecycle Extensions

### User Status & State Machine

`go-auth` persists lifecycle metadata through two columns on `users`: `status` (`pending`, `active`, `suspended`, `disabled`, `archived`) and `suspended_at` (timestamp set whenever a user enters or exits the suspended state). The default `UserStateMachine` enforces the transition graph (`archived` is terminal, `pending` can only move to `active` or `disabled`, etc.), keeps timestamps in sync, and publishes ActivitySink events.

Use the shared `Users` repository helpers (`UpdateStatus`, `Suspend`, `Reinstate`) or work directly with the state machine when you need options such as `WithTransitionReason`, `WithTransitionMetadata`, or custom hooks:

```go
auditSink := auth.ActivitySinkFunc(func(ctx context.Context, event auth.ActivityEvent) error {
    log.Printf(
        "user %s transitioned %s -> %s (reason=%v)",
        event.UserID,
        event.FromStatus,
        event.ToStatus,
        event.Metadata["reason"],
    )
    return nil
})

stateMachine := auth.NewUserStateMachine(
    repoManager.Users(),
    auth.WithStateMachineActivitySink(auditSink),
)

actor := auth.ActorRef{ID: "admin-42", Type: "admin"}
updated, err := stateMachine.Transition(
    ctx,
    actor,
    user,
    auth.UserStatusSuspended,
    auth.WithTransitionReason("manual review"),
    auth.WithTransitionMetadata(map[string]any{"ticket": "SEC-204"}),
)
if err != nil {
    panic(err)
}

fmt.Println("new status:", updated.Status, "suspended at:", updated.SuspendedAt)
```

See `examples/extensions/extensions.go` for an end-to-end sample that persists activity rows and decorates claims based on tenant context.

Transition hooks bubble failures through a configurable handler. By default `go-auth` panics with a detailed message (great for development). In production override this behavior with `auth.WithStateMachineHookErrorHandler` to convert hook failures into domain errors or alerts:

```go
handler := func(ctx context.Context, phase auth.TransitionHookPhase, err error, tc auth.TransitionContext) error {
    log.Printf("hook stage=%s user=%s error=%v", phase, tc.User.ID, err)
    return fmt.Errorf("policy hook failed: %w", err)
}

stateMachine := auth.NewUserStateMachine(
    repoManager.Users(),
    auth.WithStateMachineHookErrorHandler(handler),
)
```

### ActivitySink Wiring

`ActivitySink` is a small interface used across lifecycle transitions, login/impersonation flows, and password reset handlers:

- `ActivityEvent.EventType` distinguishes lifecycle (`user.status.changed`), login, impersonation, and password reset actions.
- `ActorRef` identifies who triggered the change (admin dashboard, API, system job).
- `Metadata` is an open map for reasons, ticket numbers, IP addresses, etc.
- Failures are logged; auth flows continue unless you wrap the sink with your own retry/alerting logic.

Configure sinks wherever lifecycle events occur:

```go
auditSink := auth.ActivitySinkFunc(func(ctx context.Context, event auth.ActivityEvent) error {
    log.Printf("activity event=%s user=%s actor=%s", event.EventType, event.UserID, event.Actor.Type)
    return nil
})

stateMachine := auth.NewUserStateMachine(users,
    auth.WithStateMachineActivitySink(auditSink),
)

auther := auth.NewAuthenticator(provider, cfg).
    WithActivitySink(auditSink)
```

The same sink can forward events to a SQL table, queue, or logging pipeline. Refer to `examples/extensions/extensions.go` for a Postgres-based implementation and batching hints.

### ClaimsDecorator Hook

Use `Auther.WithClaimsDecorator` to enrich JWTs with tenant metadata or derived resource roles before they are signed. Decorators receive the pending `JWTClaims` and **may only** mutate extension fields such as `Resources`, `Metadata`, or additional custom payload that your product documents. Core JWT claims (`sub`, `uid`, `iss`, `aud`, `iat`, `exp`) are guarded and any attempt to edit them aborts token generation.

```go
decorator := auth.ClaimsDecoratorFunc(func(ctx context.Context, identity auth.Identity, claims *auth.JWTClaims) error {
	if claims.Metadata == nil {
		claims.Metadata = map[string]any{}
	}
	claims.Metadata["tenant_id"] = lookupTenant(identity.ID())
	if claims.Resources == nil {
		claims.Resources = map[string]string{}
	}
	claims.Resources["team:"+identity.ID()] = "editor"
	return nil
})

auther := auth.NewAuthenticator(provider, cfg).
	WithClaimsDecorator(decorator)
```

If the decorator returns an error the token flow stops, the failure is logged, and no JWT is issued. Coordinate decorations with your `ActivitySink` so downstream services can reconcile claims with lifecycle transitions. Additional wiring tips and a multi-tenant example live in `examples/extensions/extensions.go`.

## API Reference

### TokenService Access

The `Authenticator` provides access to its underlying `TokenService` for advanced use cases:

```go
// Access the token service directly
tokenService := authenticator.TokenService()

// Generate tokens manually with custom resource roles
resourceRoles := map[string]string{
    "project:123": "admin",
    "files:uploads": "owner",
}
token, err := tokenService.Generate(identity, resourceRoles)

// Validate tokens manually
claims, err := tokenService.Validate(tokenString)
```

### JWT Middleware Integration

Use the `TokenService` with JWT middleware for custom authentication flows:

```go
// Create TokenServiceAdapter for jwtware middleware
tokenValidator := auth.NewTokenServiceAdapter(authenticator.TokenService())

// Configure JWT middleware
jwtConfig := jwtware.Config{
    SigningKey: jwtware.SigningKey{
        Key:    []byte(config.GetSigningKey()),
        JWTAlg: config.GetSigningMethod(),
    },
    TokenValidator: tokenValidator,
    ContextKey:     "auth",
}

middleware := jwtware.New(jwtConfig)
```

## Core Concepts

### User Roles

The library defines a hierarchical role system:

- `guest` - Read-only access
- `member` - Read and edit access
- `admin` - Read, edit, and create access
- `owner` - Full access including delete

### Resource-Level Permissions

Beyond global user roles, the library supports resource-specific permissions:

```go
// Example resource roles map
resourceRoles := map[string]string{
    "project:123":     "admin",      // Admin of project 123
    "admin:dashboard": "member",     // Member access to admin dashboard
    "files:uploads":   "owner",      // Owner of file uploads
}
```

### JWT Claims Structure

The library generates structured JWT claims:

```json
{
  "sub": "user-id",
  "uid": "user-id",
  "role": "admin",
  "res": {
    "project:123": "admin",
    "admin:dashboard": "member"
  },
  "iss": "your-app",
  "aud": ["your-audience"],
  "iat": 1234567890,
  "exp": 1234654290
}
```

## Database Schema

The library requires two database tables. Note: migrations use `TEXT` IDs in
Postgres/SQLite, while Go models cast to `uuid.UUID`. This is intentional for
now; IDs are stored as text and parsed/validated in the app. We may move to
native UUID columns in a future migration.

### Users Table

```sql
CREATE TABLE users (
    id TEXT NOT NULL PRIMARY KEY,
    user_role TEXT NOT NULL DEFAULT 'guest' CHECK (
        user_role IN ('guest', 'member', 'admin', 'owner')
    ),
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    username TEXT NOT NULL,
    profile_picture TEXT,
    email TEXT NOT NULL UNIQUE,
    phone_number TEXT,
    password_hash TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_email_verified BOOLEAN DEFAULT FALSE,
    login_attempts INTEGER DEFAULT 0,
    login_attempt_at TIMESTAMP,
    loggedin_at TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'active' CHECK (
        status IN ('pending', 'active', 'suspended', 'disabled', 'archived')
    ),
    suspended_at TIMESTAMP,
    external_id TEXT,
    external_id_provider TEXT,
    reseted_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    deleted_at TIMESTAMP
);
```

### Password Reset Table

```sql
CREATE TABLE password_reset (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    email TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown' CHECK (
        status IN ('unknown', 'requested', 'expired', 'changed')
    ),
    reseted_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    deleted_at TIMESTAMP
);
```

### Social Accounts Table

Social login adds a `social_accounts` table for linked provider identities.
Migrations ship in `data/sql/migrations` and `data/sql/migrations/sqlite`.

```sql
CREATE TABLE social_accounts (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    email TEXT,
    name TEXT,
    username TEXT,
    avatar_url TEXT,
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMP NULL,
    profile_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT uq_social_accounts_provider_id UNIQUE (provider, provider_user_id),
    CONSTRAINT uq_social_accounts_user_provider UNIQUE (user_id, provider)
);

CREATE INDEX idx_social_accounts_user_id ON social_accounts(user_id);
CREATE INDEX idx_social_accounts_provider ON social_accounts(provider, provider_user_id);
```

### Auth0 Identifiers Table (Optional Sync Track)

Auth0 sync adds a `user_identifiers` mapping table and optional external ID
columns on `users`. Migrations ship in `data/sql/migrations` and
`data/sql/migrations/sqlite`:

- `0001_auth0_identifiers.up.sql`
- `0001_auth0_identifiers.down.sql`

See `docs/AUTH0.md` for schema details and sync wiring.

## Configuration

The library uses a configuration interface that you can implement:

```go
type Config interface {
    GetSigningKey() string
    GetTokenExpiration() int
    GetExtendedTokenDuration() int
    GetIssuer() string
    GetAudience() []string
    GetContextKey() string
    GetTokenLookup() string
    GetAuthScheme() string
    GetRejectedRouteKey() string
    GetRejectedRouteDefault() string
}
```

## Authentication Flow

### User Registration

1. User submits registration form
2. Password is hashed using bcrypt
3. User record is created in database
4. Optional email verification can be triggered

### Login Process

1. User provides credentials
2. Identity provider verifies password
3. Resource role provider fetches permissions (if configured)
4. JWT token is generated with structured claims
5. Token is returned to client

### Password Reset

1. User requests password reset via email
2. Reset token is generated and stored
3. Email with reset link is sent
4. User follows link to reset password
5. New password is hashed and updated

## Middleware

### HTTP Middleware

The library provides HTTP middleware for route protection:

```go
// Protect routes requiring authentication
protectedRoute := auth.ProtectedRoute(config, errorHandler)
router.Use("/api/", protectedRoute)

// Custom authorization logic
func requireAdminRole(c router.Context) error {
    session, _ := auth.GetRouterSession(c, "auth")
    if roleSession, ok := session.(auth.RoleCapableSession); ok {
        if !roleSession.IsAtLeast("admin") {
            return c.Status(403).SendString("Forbidden")
        }
    }
    return c.Next()
}
```

### WebSocket Authentication

The library provides seamless WebSocket authentication integration with `go-router` through the `WSTokenValidator` interface:

#### Basic WebSocket Setup

```go
// Create authenticator (same as HTTP setup)
authenticator := auth.NewAuthenticator(userProvider, config)

// Create WebSocket authentication middleware using go-auth
wsAuthMiddleware := authenticator.NewWSAuthMiddleware()

// Apply to WebSocket routes
router.WS("/chat", chatHandler, wsAuthMiddleware)
```

#### Custom WebSocket Configuration

```go
// Custom WebSocket auth configuration
wsConfig := router.WSAuthConfig{
    TokenExtractor: func(req *http.Request) (string, error) {
        // Extract token from custom header
        token := req.Header.Get("X-Auth-Token")
        if token == "" {
            return "", errors.New("missing auth token")
        }
        return token, nil
    },
    // Optional: custom error handling
    ErrorHandler: func(ctx *router.WSContext, err error) {
        ctx.WriteMessage(websocket.TextMessage, []byte(`{"error": "authentication failed"}`))
        ctx.Close()
    },
}

wsAuthMiddleware := authenticator.NewWSAuthMiddleware(wsConfig)
router.WS("/secure-chat", secureHandler, wsAuthMiddleware)
```

#### Using Authentication in WebSocket Handlers

```go
func chatHandler(ctx *router.WSContext) error {
    // Get authenticated user claims
    claims, ok := auth.WSAuthClaimsFromContext(ctx.Context())
    if !ok {
        return errors.New("no authentication claims found")
    }

    userID := claims.UserID()
    userRole := claims.Role()

    // Use resource-level permissions
    canModerate := claims.CanEdit("chat:moderation")
    canBroadcast := claims.CanCreate("chat:announcements")

    // Your WebSocket logic here
    for {
        messageType, message, err := ctx.ReadMessage()
        if err != nil {
            break
        }

        // Process message based on user permissions
        if canModerate && isModerateCommand(message) {
            handleModerationCommand(message, userID)
        } else {
            handleRegularMessage(message, userID)
        }
    }

    return nil
}
```

#### Advanced WebSocket Authentication

For more complex scenarios, you can create a custom token validator:

```go
// Custom validator for additional WebSocket-specific logic
type CustomWSValidator struct {
    tokenService auth.TokenService
    logger       Logger
}

func (v *CustomWSValidator) Validate(tokenString string) (router.WSAuthClaims, error) {
    // Use go-auth token service for validation
    claims, err := v.tokenService.Validate(tokenString)
    if err != nil {
        v.logger.Error("WebSocket token validation failed", "error", err)
        return nil, err
    }

    // Additional WebSocket-specific validation
    if !claims.CanRead("websocket:access") {
        return nil, errors.New("insufficient permissions for WebSocket access")
    }

    // Return adapter for go-router compatibility
    return &auth.WSAuthClaimsAdapter{Claims: claims}, nil
}

// Use custom validator
validator := &CustomWSValidator{
    tokenService: authenticator.TokenService(),
    logger:       logger,
}

wsConfig := router.WSAuthConfig{TokenValidator: validator}
wsAuth := router.NewWSAuth(wsConfig)
```

## Command Handlers

The library includes command handlers for common operations:

```go
// Register user
registerUser := auth.RegisterUserHandler{repo: repositoryManager}
err := registerUser.Execute(ctx, auth.RegisterUserMessage{
    FirstName: "John",
    LastName:  "Doe",
    Email:     "john@example.com",
    Password:  "securepassword",
})

// Initialize password reset
initReset := auth.InitializePasswordResetHandler{repo: repositoryManager}
err := initReset.Execute(ctx, auth.InitializePasswordResetMessage{
    Email: "user@example.com",
    Stage: "show-reset",
})
```
