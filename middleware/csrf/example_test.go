//go:build ignore

package csrf_test

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/middleware/csrf"
	"github.com/goliatone/go-router"
)

// Example: Basic CSRF protection
func ExampleNew_basic() {
	app := router.New()

	// Add CSRF protection
	app.Use(csrf.New())

	app.Get("/form", func(ctx router.Context) error {
		// CSRF token is available in ctx.Locals("csrf_token")
		return ctx.SendString("Form page")
	})

	app.Post("/submit", func(ctx router.Context) error {
		// POST request will be validated for CSRF token
		return ctx.SendString("Form submitted successfully")
	})

	app.Listen(":8080")
}

// Example: CSRF with custom configuration
func ExampleNew_withConfig() {
	app := router.New()

	// Configure CSRF middleware
	app.Use(csrf.New(csrf.Config{
		TokenLength:   32,
		ContextKey:    "csrf_token",
		FormFieldName: "_token",
		HeaderName:    "X-CSRF-Token",
		SafeMethods:   []string{"GET", "HEAD", "OPTIONS"},
		Expiration:    24 * time.Hour,
		Skip: func(ctx router.Context) bool {
			// Skip CSRF for API endpoints
			return strings.HasPrefix(ctx.Path(), "/api/")
		},
	}))

	app.Listen(":8080")
}

// Example: Template integration
func ExampleCSRFTemplateHelpers() {
	app := router.New()

	// Add CSRF middleware
	app.Use(csrf.New())

	// Render template with CSRF helpers
	app.Get("/form", func(ctx router.Context) error {
		// Get template helpers with CSRF token from context
		helpers := auth.TemplateHelpersWithRouter(ctx, auth.TemplateUserKey)

		// In a real app, you'd use your template renderer here
		// The helpers map contains csrf_token, csrf_field, etc.
		_ = helpers

		return ctx.SendString("Form with CSRF protection")
	})

	app.Listen(":8080")
}

// Example: Custom error handling
func ExampleNew_customErrorHandler() {
	app := router.New()

	app.Use(csrf.New(csrf.Config{
		ErrorHandler: func(ctx router.Context, err error) error {
			switch err {
			case csrf.ErrTokenMissing:
				return ctx.Status(400).JSON(map[string]string{
					"error": "CSRF token is required",
					"code":  "CSRF_TOKEN_MISSING",
				})
			case csrf.ErrTokenMismatch:
				return ctx.Status(403).JSON(map[string]string{
					"error": "Invalid CSRF token",
					"code":  "CSRF_TOKEN_INVALID",
				})
			default:
				return ctx.Status(500).JSON(map[string]string{
					"error": "CSRF validation failed",
					"code":  "CSRF_VALIDATION_ERROR",
				})
			}
		},
	}))

	app.Listen(":8080")
}

// Simple in memory storage implementation for testing
type memoryStorage struct {
	data map[string]string
}

func newMemoryStorage() *memoryStorage {
	return &memoryStorage{
		data: make(map[string]string),
	}
}

func (m *memoryStorage) Get(key string) (string, error) {
	if value, exists := m.data[key]; exists {
		return value, nil
	}
	return "", nil
}

func (m *memoryStorage) Set(key string, value string, expiration time.Duration) error {
	m.data[key] = value
	return nil
}

func (m *memoryStorage) Delete(key string) error {
	delete(m.data, key)
	return nil
}

// Example: Using storage backend
func ExampleNew_withStorage() {
	app := router.New()

	storage := newMemoryStorage()

	app.Use(csrf.New(csrf.Config{
		Storage:    storage,
		Expiration: 24 * time.Hour,
	}))

	app.Listen(":8080")
}

// Test helper to demonstrate token extraction and usage
func TestCSRFTokenFlow(t *testing.T) {
	app := router.New()

	// Add CSRF middleware
	app.Use(csrf.New())

	// Route that generates a form with CSRF token
	app.Get("/form", func(ctx router.Context) error {
		token := ctx.Locals("csrf_token").(string)
		form := `
		<form method="POST" action="/submit">
			<input type="hidden" name="_token" value="` + token + `">
			<input type="text" name="data" value="test">
			<button type="submit">Submit</button>
		</form>`
		return ctx.Type("html").SendString(form)
	})

	// Route that processes the form
	app.Post("/submit", func(ctx router.Context) error {
		data := ctx.FormValue("data")
		return ctx.SendString("Received: " + data)
	})

	// Test: GET request to get the form with token
	req := httptest.NewRequest("GET", "/form", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// In a real test, you'd extract the token from the response body
	// For this example, we'll just demonstrate the flow

	// Test: POST request with valid token (would need to extract from GET response)
	form := url.Values{}
	form.Add("_token", "mock-token") // In real test, extract from GET response
	form.Add("data", "test-value")

	req = httptest.NewRequest("POST", "/submit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// This would fail because we're using a mock token
	resp, err = app.Test(req)
	if err != nil {
		t.Fatal(err)
	}

	// In a real test with proper token extraction, this would be 200
	// With our mock token, it should be 403 (forbidden)
	if resp.StatusCode != 403 {
		t.Errorf("Expected status 403 for invalid token, got %d", resp.StatusCode)
	}
}

// Example: Integration with authentication middleware
func ExampleNew_withAuthentication() {
	app := router.New()

	// First, add JWT authentication middleware
	// (this would be configured with your actual JWT settings)
	/*
		app.Use(jwtware.New(jwtware.Config{
			TokenValidator:  yourTokenValidator,
			TemplateUserKey: "current_user",
		}))
	*/

	// Then add CSRF protection
	app.Use(csrf.New())

	// Protected route requiring both authentication and CSRF protection
	app.Post("/user/update", func(ctx router.Context) error {
		// Both JWT and CSRF validation have passed
		user := ctx.Locals("current_user")
		token := ctx.Locals("csrf_token")

		_ = user  // Current authenticated user
		_ = token // CSRF token for this request

		return ctx.SendString("User updated successfully")
	})

	app.Listen(":8080")
}
