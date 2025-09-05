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
- Built-in authentication controllers for web applications
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

### Enhanced Resource-Level Permissions

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

    return c.JSON(map[string]interface{}{
        "user_id": session.GetUserID(),
        "data": session.GetData(),
    })
}
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
