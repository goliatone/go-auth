# Auto-Context Template Integration

`go-auth` provides automatic user context registration for templates, making it seamless to access current user information without manual context management.

## Features

- **Automatic User Injection**: JWT middleware can automatically store user data in router context for templates
- **Flexible User Providers**: Convert AuthClaims to full User objects or use claims directly
- **Multiple Integration Patterns**: Context-aware helpers and convenience functions
- **Zero Template Changes**: Works with existing template helpers and functions

## Quick Start

### 1. Setup JWT Middleware with Template Support

```go
import (
    "github.com/goliatone/go-auth"
    "github.com/goliatone/go-auth/middleware/jwtware"
    "github.com/goliatone/go-template"
)

// Setup JWT middleware with automatic template context
jwtMiddleware := jwtware.New(jwtware.Config{
    TokenValidator: tokenService,           // Your token service
    ContextKey: "user",                     // For AuthClaims (standard)
    TemplateUserKey: "current_user",        // For template usage  
    UserProvider: func(claims jwtware.AuthClaims) (any, error) {
        // Optional: Convert claims to full User object
        return userRepo.GetByID(claims.UserID())
    },
})

// Setup template renderer (once, globally)
renderer, err := template.NewRenderer(
    template.WithBaseDir("./templates"),
    template.WithGlobalData(auth.TemplateHelpers()),
)
```

### 2. Use in Route Handlers

```go
// Option A: Use context-aware helpers (Recommended)
func dashboardHandler(ctx router.Context) error {
    // Get user-aware template helpers from router context
    templateData := auth.TemplateHelpersWithRouter(ctx, "current_user")
    
    // Add your route-specific data
    templateData["posts"] = posts
    templateData["notifications"] = notifications
    
    result, err := renderer.RenderTemplate("dashboard", templateData)
    return ctx.SendString(result)
}

// Option B: Extract user manually
func profileHandler(ctx router.Context) error {
    user, ok := auth.GetTemplateUser(ctx, "current_user")
    if !ok {
        return ctx.Status(401).SendString("Unauthorized")
    }
    
    data := map[string]any{
        "current_user": user,
        "profile": userProfile,
    }
    
    result, err := renderer.RenderTemplate("profile", data)
    return ctx.SendString(result)
}
```

### 3. Use in Templates

Templates automatically have access to the current user and all auth helpers:

```html
<!-- Navigation with automatic user detection -->
<nav class="navbar">
  {% if current_user|is_authenticated %}
    <span class="user-info">
      Welcome, {{ current_user.first_name }}! 
      ({{ current_user.user_role|title }})
    </span>
    
    <ul class="nav-menu">
      {% if current_user|can_create %}
        <li><a href="/posts/create">Create Post</a></li>
      {% endif %}
      
      {% if current_user|has_role:"admin" %}
        <li><a href="/admin">Admin Panel</a></li>
      {% endif %}
    </ul>
    
    <a href="/logout">Logout</a>
  {% else %}
    <div class="auth-buttons">
      <a href="/login" class="btn">Login</a>
      <a href="/register" class="btn">Register</a>
    </div>
  {% endif %}
</nav>

<!-- Content with permission-based rendering -->
<div class="content">
  {% if current_user|can_edit %}
    <button class="btn btn-primary">Edit Content</button>
  {% endif %}
  
  {% if current_user|is_at_least:"admin" %}
    <div class="admin-tools">
      <h3>Admin Tools</h3>
      <!-- Admin-only content -->
    </div>
  {% endif %}
</div>
```

## Configuration Options

### JWT Middleware Template Fields

| Field | Type | Description |
|-------|------|-------------|
| `TemplateUserKey` | `string` | Key for storing user in router context for templates (default: "") |
| `UserProvider` | `func(AuthClaims) (any, error)` | Optional converter from claims to User object |

### Template Helper Functions

| Function | Description | Works With |
|----------|-------------|------------|
| `TemplateHelpers()` | Basic helpers without user context | Manual user injection |
| `TemplateHelpersWithUser(user)` | Helpers with global user set | Static user object |
| `TemplateHelpersWithRouter(ctx, key)` | Context-aware helpers | Router context |
| `MergeTemplateData(ctx, data)` | Copies helpers + request data into a single view map | Router context |
| `GetTemplateUser(ctx, key)` | Extract user from router context | Any user type |

> `csrf_field`, `csrf_token`, and `csrf_meta` are exposed as lazy helpers, so registering `auth.TemplateHelpers()` globally is enough for go-auth’s Django templates to render fresh CSRF tokens on every request. Use `MergeTemplateData` when you need concrete strings (e.g., when passing the context to JSON or tests).

## Integration Patterns

### Pattern 1: Middleware + Context Helpers (Recommended)

**Best for**: Production applications with consistent user context needs

```go
// Setup once
jwtMiddleware := jwtware.New(jwtware.Config{
    TokenValidator: tokenService,
    TemplateUserKey: "current_user",
    UserProvider: userService.GetByID, // Full user objects
})

renderer, _ := template.NewRenderer(
    template.WithBaseDir("./templates"),
    template.WithGlobalData(auth.TemplateHelpers()),
)

// Use in handlers
func handler(ctx router.Context) error {
    data := auth.MergeTemplateData(ctx, router.ViewContext{
        "page_data": pageSpecificData,
    })

    result, _ := renderer.RenderTemplate("page", data)
    return ctx.SendString(result)
}
```

### Pattern 2: Claims as User Data

**Best for**: Simple applications that don't need full User objects

```go
jwtMiddleware := jwtware.New(jwtware.Config{
    TokenValidator: tokenService,
    TemplateUserKey: "current_user",
    // No UserProvider - uses AuthClaims directly
})

// Templates work the same way with AuthClaims
// {% if current_user|has_role:"admin" %}
```

### Pattern 3: Manual Context Management

**Best for**: Custom scenarios or gradual migration

```go
func handler(ctx router.Context) error {
    // Get user manually
    if user, ok := auth.GetTemplateUser(ctx, "current_user"); ok {
        data := map[string]any{
            "current_user": user,
            "page_content": content,
        }
        result, _ := renderer.RenderTemplate("page", data)
        return ctx.SendString(result)
    }
    
    return ctx.Redirect("/login")
}
```

## Supported User Types

The template helpers automatically handle different user data types:

### 1. Full User Objects
```go
UserProvider: func(claims jwtware.AuthClaims) (any, error) {
    return &auth.User{
        ID: uuid.MustParse(claims.UserID()),
        Role: auth.UserRole(claims.Role()),
        FirstName: "John",
        // ... other fields
    }, nil
}
```

### 2. AuthClaims (JWT Claims)
```go
// No UserProvider needed - AuthClaims used directly
// Supports: UserID(), Role(), HasRole(), CanRead(), etc.
```

### 3. JSON-Converted Maps
```go
// Automatically handled when go-template converts structs to JSON
// Works with: user_role, id, first_name, etc. fields
```

### 4. Custom Types
Implement the AuthClaims interface for custom user types:

```go
type CustomUser struct {
    // Your fields
}

func (u *CustomUser) UserID() string { /* ... */ }
func (u *CustomUser) Role() string { /* ... */ }
func (u *CustomUser) HasRole(role string) bool { /* ... */ }
// ... other AuthClaims methods
```

## Error Handling

The integration is designed to be fault-tolerant:

- **UserProvider errors**: Falls back to using AuthClaims
- **Missing users**: Template functions return `false` for permissions
- **Invalid types**: Safely handled with default `false` returns
- **Context misses**: Templates continue to work without user context

## Performance Considerations

- **Template Helpers**: Called once per request, minimal overhead
- **User Providers**: Cached by your user service (recommended)
- **Router Context**: Very fast key-value lookups
- **AuthClaims vs User Objects**: Claims are faster, User objects more feature-rich

## Migration Guide

### From Manual User Injection

**Before**:
```go
func handler(ctx router.Context) error {
    user := getCurrentUser(ctx)
    data := map[string]any{
        "current_user": user,
        "content": content,
    }
    // Template rendering...
}
```

**After**:
```go
// Setup middleware once with TemplateUserKey
func handler(ctx router.Context) error {
    data := auth.TemplateHelpersWithRouter(ctx, "current_user")
    data["content"] = content
    // Template rendering...
}
```

### From Global Template Context

**Before**:
```go
renderer, _ := template.NewRenderer(
    template.WithGlobalData(auth.TemplateHelpersWithUser(staticUser)),
)
```

**After**:
```go
// Dynamic per-request user context
renderer, _ := template.NewRenderer(
    template.WithGlobalData(auth.TemplateHelpers()),
)

// In handlers:
data := auth.TemplateHelpersWithRouter(ctx, "current_user")
```

## Examples

See complete working examples in:
- [`examples/template_integration_example.go`](examples/template_integration_example.go)
- [`TEMPLATE_INTEGRATION.md`](TEMPLATE_INTEGRATION.md)

## Security Notes

- User data is automatically injected only after successful JWT validation
- Permission checks use the same role hierarchy as your auth system
- Template helpers safely handle nil/invalid user data
- No sensitive data exposure (uses same AuthClaims interface)

The auto-context integration makes authentication-aware templates effortless while maintaining full security and flexibility!
