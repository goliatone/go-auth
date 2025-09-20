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
helpers := auth.TemplateHelpersWithRouter(ctx, auth.TemplateUserKey)

// `helpers` now contains:
// - csrf_token(): returns the actual token string
// - csrf_field():  `<input type="hidden" name="_token" ...>` (respects custom name)
// - csrf_meta():   `<meta name="csrf-token" ...>`
// - csrf_header_name(): header to use for AJAX requests

return ctx.Render("form", helpers)
```

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

The library requires two database tables:

### Users Table

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    user_role VARCHAR NOT NULL,
    first_name VARCHAR NOT NULL,
    last_name VARCHAR NOT NULL,
    username VARCHAR UNIQUE NOT NULL,
    email VARCHAR UNIQUE NOT NULL,
    phone_number VARCHAR,
    password_hash VARCHAR,
    is_email_verified BOOLEAN DEFAULT FALSE,
    login_attempts INTEGER DEFAULT 0,
    login_attempt_at TIMESTAMP,
    loggedin_at TIMESTAMP,
    metadata JSONB,
    reseted_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);
```

### Password Reset Table

```sql
CREATE TABLE password_reset (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    status VARCHAR NOT NULL,
    email VARCHAR NOT NULL,
    reseted_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);
```

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
