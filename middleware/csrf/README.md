# CSRF Middleware

A CSRF (Cross-Site Request Forgery) protection middleware for go-router that integrates seamlessly with the go-auth template system.

## Features

- **Cryptographically secure token generation** using `crypto/rand`
- **Stateless or stateful operation** (with optional storage backend)
- **Template integration** with helper functions for easy token embedding
- **Flexible token validation** from forms, headers, or custom extractors
- **Configurable safe methods** (GET, HEAD, OPTIONS, TRACE by default)
- **Session-based token storage** with automatic key generation

## Basic Usage

### 1. Simple Stateless Protection

```go
package main

import (
    "github.com/goliatone/go-auth/middleware/csrf"
    "github.com/goliatone/go-router"
)

func main() {
    app := router.New()

    // Add CSRF middlware
    app.Use(csrf.New())

    app.Listen(":8080")
}
```

### 2. With Custom Configuration

```go
// Configure CSRF middleware
app.Use(csrf.New(csrf.Config{
    TokenLength:   32,                    // Token length in bytes
    ContextKey:    "csrf_token",          // Key for storing token in context
    FormFieldName: "_token",              // Form field name for token
    HeaderName:    "X-CSRF-Token",        // Header name for token
    SafeMethods:   []string{"GET", "HEAD", "OPTIONS"},
    Expiration:    24 * time.Hour,        // Token expiration (when using storage)
    TokenLookup:   "form:_token,header:X-CSRF-Token",
    Skip: func(ctx router.Context) bool {
        // Skip CSRF for API endpoints
        return strings.HasPrefix(ctx.Path(), "/api/")
    },
}))
```

### 3. With Storage Backend

```go
// Using a custom storage implementation
type redisStorage struct {
    client *redis.Client
}

func (r *redisStorage) Get(key string) (string, error) {
    return r.client.Get(context.Background(), key).Result()
}

func (r *redisStorage) Set(key string, value string, expiration time.Duration) error {
    return r.client.Set(context.Background(), key, value, expiration).Err()
}

func (r *redisStorage) Delete(key string) error {
    return r.client.Del(context.Background(), key).Err()
}

// Use with middleware
app.Use(csrf.New(csrf.Config{
    Storage: &redisStorage{client: redisClient},
    Expiration: 24 * time.Hour,
}))
```

## Template Integration

The middleware integrates with the go-auth template system to provide easy access to CSRF tokens in templates.

### 1. Setup Template Helpers

```go
import (
    "github.com/goliatone/go-auth"
    "github.com/goliatone/go-template"
)

// Method 1: Global helpers (tokens won't be actual values)
renderer, err := template.NewRenderer(
    template.WithBaseDir("./templates"),
    template.WithGlobalData(auth.TemplateHelpers()),
)

// Method 2: Per-request helpers (recommended)
func renderTemplate(ctx router.Context, name string, data map[string]any) error {
    // Get helpers with actual CSRF token from context
    globalData := auth.TemplateHelpersWithRouter(ctx, auth.TemplateUserKey)

    // Merge with your template data
    templateData := make(map[string]any)
    for k, v := range globalData {
        templateData[k] = v
    }
    for k, v := range data {
        templateData[k] = v
    }

    return ctx.Render(name, templateData)
}
```

### 2. Template Usage

In your Django/Pongo2 templates:

```html
<!-- Hidden form field -->
<form method="POST" action="/submit">
    {{ csrf_field }}
    <input type="text" name="data" value="test">
    <button type="submit">Submit</button>
</form>

<!-- Manual hidden field -->
<form method="POST" action="/submit">
    <input type="hidden" name="_token" value="{{ csrf_token }}">
    <input type="text" name="data" value="test">
    <button type="submit">Submit</button>
</form>

<!-- Meta tag for JavaScript -->
<head>
    {{ csrf_meta }}
</head>

<!-- JavaScript usage -->
<script>
    const token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    fetch('/api/data', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            '{{ csrf_header_name }}': token
        },
        body: JSON.stringify({data: 'value'})
    });
</script>
```

## Available Template Functions

| Function | Description | Output |
|----------|-------------|--------|
| `csrf_token` | Returns the CSRF token string | `"abc123def456..."` |
| `csrf_field` | Returns a hidden input field with token | `<input type="hidden" name="_token" value="...">` |
| `csrf_meta` | Returns a meta tag with token | `<meta name="csrf-token" content="...">` |
| `csrf_header_name` | Returns the default header name | `"X-CSRF-Token"` |

## Advanced Configuration

### Error Handling

```go
app.Use(csrf.New(csrf.Config{
    ErrorHandler: func(ctx router.Context, err error) error {
        if err == csrf.ErrTokenMissing {
            return ctx.Status(400).JSON(map[string]string{
                "error": "CSRF token is required",
            })
        }
        if err == csrf.ErrTokenMismatch {
            return ctx.Status(403).JSON(map[string]string{
                "error": "Invalid CSRF token",
            })
        }
        return ctx.Status(500).JSON(map[string]string{
            "error": "CSRF validation failed",
        })
    },
}))
```

### Custom Token Extraction

```go
app.Use(csrf.New(csrf.Config{
    TokenLookup: "form:_token,header:X-CSRF-Token,query:csrf_token",
}))
```

### Integration with Authentication

```go
// Use CSRF with JWT middleware
app.Use(jwtware.New(jwtware.Config{
    TokenValidator: tokenService,
    TemplateUserKey: "current_user",
}))

app.Use(csrf.New(csrf.Config{
    // CSRF tokens will be associated with user sessions
    // when user_id is available in context
}))

// In your route handler
app.Post("/protected", func(ctx router.Context) error {
    // Both JWT and CSRF validation have passed
    return renderTemplate(ctx, "success.html", map[string]any{
        "message": "Form submitted successfully!",
    })
})
```

## Token Storage Keys

The middleware automatically generates storage keys based on available context:

1. **Session ID**: `csrf_` + session_id (from `ctx.Locals("session_id")`)
2. **User ID**: `csrf_user_` + user_id (from `ctx.Locals("user_id")`)
3. **IP Address**: `csrf_ip_` + client_ip (fallback)

## Security Considerations

1. **Use HTTPS**: Always use HTTPS in production to prevent token interception
2. **Token Rotation**: Tokens are rotated per request in stateless mode, or can expire with storage
3. **Same-Origin Policy**: Tokens are tied to the origin that generated them
4. **Storage Security**: When using storage backends, ensure they're properly secured
5. **Error Handling**: Don't leak sensitive information in error messages

## Testing

```go
func TestCSRFProtection(t *testing.T) {
    app := router.New()
    app.Use(csrf.New())

    app.Post("/test", func(ctx router.Context) error {
        return ctx.SendString("OK")
    })

    // Get token first
    req := httptest.NewRequest("GET", "/test", nil)
    resp, _ := app.Test(req)

    // Extract token from response...
    token := extractTokenFromResponse(resp)

    // Use token in POST request
    form := url.Values{}
    form.Add("_token", token)

    req = httptest.NewRequest("POST", "/test", strings.NewReader(form.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, _ = app.Test(req)
    assert.Equal(t, 200, resp.StatusCode)
}
```
