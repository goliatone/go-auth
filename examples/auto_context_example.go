package main

import (
	"fmt"
	"log"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/middleware/jwtware"
	"github.com/goliatone/go-router"
	"github.com/goliatone/go-template"
	"github.com/google/uuid"
)

// MockTokenService implements jwtware.TokenValidator for demonstration
type MockTokenService struct{}

func (m *MockTokenService) Validate(tokenString string) (jwtware.AuthClaims, error) {
	// In a real app, this would validate the JWT and return claims
	return &auth.JWTClaims{
		UID:      "user-123",
		UserRole: "admin",
	}, nil
}

// MockUserService simulates a user repository
type MockUserService struct{}

func (m *MockUserService) GetByID(userID string) (*auth.User, error) {
	// In a real app, this would fetch from database
	return &auth.User{
		ID:        uuid.New(),
		Role:      auth.RoleAdmin,
		FirstName: "John",
		LastName:  "Doe",
		Username:  "johndoe",
		Email:     "john@example.com",
	}, nil
}

// MockRouterContext implements router.Context for demonstration
type MockRouterContext struct {
	locals map[string]any
}

func NewMockRouterContext() *MockRouterContext {
	return &MockRouterContext{
		locals: make(map[string]any),
	}
}

func (m *MockRouterContext) Locals(key string, value ...any) any {
	if len(value) > 0 {
		m.locals[key] = value[0]
		return value[0]
	}
	return m.locals[key]
}

// Minimal router.Context implementation for demo
func (m *MockRouterContext) Next() error                      { return nil }
func (m *MockRouterContext) JSON(data any) error              { return nil }
func (m *MockRouterContext) Status(code int) router.Context   { return m }
func (m *MockRouterContext) SendString(s string) error        { return nil }
func (m *MockRouterContext) Context() interface{}             { return nil }
func (m *MockRouterContext) SetContext(ctx interface{})       {}
func (m *MockRouterContext) GetString(key, def string) string { return "" }
func (m *MockRouterContext) Query(key, def string) string     { return "" }
func (m *MockRouterContext) Param(key string) string          { return "" }
func (m *MockRouterContext) Cookies(key string) string        { return "" }

func main() {
	fmt.Println("=== Auto-Context Template Integration Example ===")

	// 1. Setup Services
	tokenService := &MockTokenService{}
	userService := &MockUserService{}

	// 2. Setup JWT Middleware with Template Support
	fmt.Println("\n1. JWT Middleware Configuration:")
	fmt.Println("   - ContextKey: 'user' (for AuthClaims)")
	fmt.Println("   - TemplateUserKey: 'current_user' (for templates)")
	fmt.Println("   - UserProvider: converts claims to User objects")

	jwtConfig := jwtware.Config{
		TokenValidator:  tokenService,
		ContextKey:      "user",         // Standard claims key
		TemplateUserKey: "current_user", // Template user key
		UserProvider: func(claims jwtware.AuthClaims) (any, error) {
			// Convert AuthClaims to full User object
			return userService.GetByID(claims.UserID())
		},
	}
	_ = jwtConfig // In real app: jwtware.New(jwtConfig)

	// 3. Setup Template Renderer (Global)
	fmt.Println("\n2. Template Renderer Setup:")
	fmt.Println("   - Uses TemplateHelpers() for base auth functions")
	fmt.Println("   - No user context needed at initialization")

	renderer, err := template.NewRenderer(
		template.WithBaseDir("/tmp"), // Using /tmp for demo
		template.WithGlobalData(auth.TemplateHelpers()),
	)
	if err != nil {
		log.Fatal(err)
	}

	// 4. Simulate Middleware Processing
	fmt.Println("\n3. Middleware Processing Simulation:")
	ctx := NewMockRouterContext()

	// Simulate what JWT middleware would do:
	// Step 1: Validate token and get claims
	claims, err := tokenService.Validate("mock-jwt-token")
	if err != nil {
		log.Fatal(err)
	}

	// Step 2: Store claims in router context
	ctx.Locals("user", claims)

	// Step 3: Get user object via UserProvider
	userObj, err := userService.GetByID(claims.UserID())
	if err != nil {
		log.Fatal(err)
	}

	// Step 4: Store user object for templates
	ctx.Locals("current_user", userObj)

	fmt.Printf("   - Claims stored under 'user' key: %+v\n", claims)
	fmt.Printf("   - User object stored under 'current_user' key: %s (%s)\n",
		userObj.Username, userObj.Role)

	// 5. Route Handler Examples
	fmt.Println("\n4. Route Handler Examples:")

	// Pattern A: Context-Aware Helpers (Recommended)
	fmt.Println("\n   Pattern A: Context-Aware Helpers")
	templateData := auth.TemplateHelpersWithRouter(ctx, "current_user")

	// Add route-specific data
	templateData["page_title"] = "Dashboard"
	templateData["posts"] = []map[string]any{
		{"id": 1, "title": "First Post", "author": "John"},
		{"id": 2, "title": "Second Post", "author": "Jane"},
	}

	fmt.Printf("   - Template data keys: %v\n", getMapKeys(templateData))
	fmt.Printf("   - Current user available: %t\n", templateData["current_user"] != nil)

	// Pattern B: Manual User Extraction
	fmt.Println("\n   Pattern B: Manual User Extraction")
	if user, ok := auth.GetTemplateUser(ctx, "current_user"); ok {
		fmt.Printf("   - Extracted user: %s\n", user.(*auth.User).Username)
		fmt.Printf("   - User authenticated: %t\n", true)
	}

	// 6. Template Examples
	fmt.Println("\n5. Template Usage Examples:")

	// Navigation template
	navTemplate := `
<nav class="navbar">
  {% if current_user|is_authenticated %}
    <span class="user-info">
      Welcome, {{ current_user.first_name }}!
      ({{ current_user.user_role|title }})
    </span>

    <ul class="nav-menu">
      <li><a href="/dashboard">Dashboard</a></li>

      {% if current_user|can_create %}
        <li><a href="/posts/create">Create Post</a></li>
      {% endif %}

      {% if current_user|has_role:"admin" %}
        <li><a href="/admin">Admin Panel</a></li>
      {% endif %}

      {% if current_user|is_at_least:"owner" %}
        <li><a href="/system">System Settings</a></li>
      {% endif %}
    </ul>

    <a href="/logout" class="logout-btn">Logout</a>
  {% else %}
    <div class="auth-buttons">
      <a href="/login" class="btn">Login</a>
      <a href="/register" class="btn">Register</a>
    </div>
  {% endif %}
</nav>`

	fmt.Println("\n   Navigation Template:")
	result, err := renderer.RenderString(navTemplate, templateData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result)

	// Permission-based content template
	contentTemplate := `
<div class="content">
  <h1>{{ page_title }}</h1>

  {% if current_user|can_edit %}
    <div class="editor-tools">
      <button class="btn btn-primary">Edit Mode</button>
      <button class="btn btn-secondary">Save Draft</button>
    </div>
  {% endif %}

  <div class="posts">
    {% for post in posts %}
      <div class="post">
        <h3>{{ post.title }}</h3>
        <p>by {{ post.author }}</p>

        {% if current_user|can_edit %}
          <a href="/posts/{{ post.id }}/edit" class="btn btn-sm">Edit</a>
        {% endif %}

        {% if current_user|can_delete %}
          <button class="btn btn-sm btn-danger">Delete</button>
        {% endif %}
      </div>
    {% endfor %}
  </div>

  {% if current_user|has_role:"admin" %}
    <div class="admin-panel">
      <h3>Admin Tools</h3>
      <p>Admin-only content visible here</p>
    </div>
  {% endif %}
</div>`

	fmt.Println("\n   Content Template:")
	result, err = renderer.RenderString(contentTemplate, templateData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result)

	// 7. Demonstrate Different User Types
	fmt.Println("\n6. Different User Types:")

	// Using AuthClaims directly (no UserProvider)
	fmt.Println("\n   With AuthClaims (no UserProvider):")
	claimsCtx := NewMockRouterContext()
	claimsCtx.Locals("current_user", claims)
	claimsData := auth.TemplateHelpersWithRouter(claimsCtx, "current_user")

	claimsTemplate := `User ID: {{ current_user.uid }}, Role: {{ current_user.role }}, Has Admin: {{ current_user|has_role:"admin" }}`
	result, err = renderer.RenderString(claimsTemplate, claimsData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Result: %s\n", result)

	// Using JSON-converted user (simulating template conversion)
	fmt.Println("\n   With JSON-converted User:")
	jsonUser := map[string]any{
		"id":         "user-456",
		"user_role":  "member",
		"first_name": "Jane",
		"last_name":  "Smith",
		"username":   "janesmith",
	}
	jsonCtx := NewMockRouterContext()
	jsonCtx.Locals("current_user", jsonUser)
	jsonData := auth.TemplateHelpersWithRouter(jsonCtx, "current_user")

	jsonTemplate := `User: {{ current_user.first_name }}, Role: {{ current_user.user_role }}, Can Create: {{ current_user|can_create }}`
	result, err = renderer.RenderString(jsonTemplate, jsonData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Result: %s\n", result)

	fmt.Println("\n=== Integration Benefits ===")
	fmt.Println("✓ Automatic user context injection")
	fmt.Println("✓ No template changes required")
	fmt.Println("✓ Works with AuthClaims or User objects")
	fmt.Println("✓ Fault-tolerant error handling")
	fmt.Println("✓ Consistent permission checking")
	fmt.Println("✓ Zero configuration templates")

	fmt.Println("\n=== Usage in Your App ===")
	fmt.Println("1. Configure JWT middleware with TemplateUserKey")
	fmt.Println("2. Use auth.TemplateHelpersWithRouter() in handlers")
	fmt.Println("3. Templates automatically have current_user available")
	fmt.Println("4. All auth helpers work seamlessly")
}

// Helper function to get map keys for demonstration
func getMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
