package auth

import (
	"testing"
	"time"

	"github.com/flosch/pongo2/v6"

	csfmw "github.com/goliatone/go-auth/middleware/csrf"
	"github.com/goliatone/go-router"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplateHelpers(t *testing.T) {
	helpers := TemplateHelpers()

	// Test that all expected helpers are present
	expectedHelpers := []string{
		"is_authenticated",
		"has_role",
		"is_at_least",
		"can_read",
		"can_edit",
		"can_create",
		"can_delete",
		"can_access",
		"roles",
	}

	for _, helper := range expectedHelpers {
		assert.Contains(t, helpers, helper, "Expected helper %s should be present", helper)
	}

	// Test roles constant map
	roles, ok := helpers["roles"].(map[string]string)
	require.True(t, ok, "roles should be a map[string]string")
	assert.Equal(t, string(RoleGuest), roles["guest"])
	assert.Equal(t, string(RoleMember), roles["member"])
	assert.Equal(t, string(RoleAdmin), roles["admin"])
	assert.Equal(t, string(RoleOwner), roles["owner"])
}

func TestTemplateHelpersCSRFLazyFunction(t *testing.T) {
	helpers := TemplateHelpers()

	fn, ok := helpers["csrf_field"].(func(*pongo2.ExecutionContext) string)
	require.True(t, ok, "csrf_field should be exposed as lazy function")

	token := "lazy-token"
	execCtx := &pongo2.ExecutionContext{
		Public: pongo2.Context{
			csfmw.DefaultTemplateHelpersKey: map[string]any{
				"csrf_field": `<input type="hidden" name="_token" value="` + token + `">`,
			},
		},
	}

	resolved := fn(execCtx)
	require.NotEmpty(t, resolved)
	assert.Contains(t, resolved, token)
}

func TestTemplateHelpersCSRFFallback(t *testing.T) {
	helpers := TemplateHelpers()

	fn, ok := helpers["csrf_meta"].(func(*pongo2.ExecutionContext) string)
	require.True(t, ok, "csrf_meta should be exposed as lazy function")

	execCtx := &pongo2.ExecutionContext{
		Public: pongo2.Context{},
	}

	expected := `<meta name="csrf-token" content="">`
	assert.Equal(t, expected, fn(execCtx))
}

func TestTemplateHelpersWithUser(t *testing.T) {
	user := &User{
		ID:        uuid.New(),
		Role:      RoleAdmin,
		FirstName: "John",
		LastName:  "Doe",
		Username:  "johndoe",
		Email:     "john@example.com",
		CreatedAt: &time.Time{},
	}

	helpers := TemplateHelpersWithUser(user)

	// Test that all basic helpers are still present
	assert.Contains(t, helpers, "is_authenticated")
	assert.Contains(t, helpers, "has_role")

	// Test that current_user is set
	currentUser, ok := helpers["current_user"].(*User)
	require.True(t, ok, "current_user should be a *User")
	assert.Equal(t, user, currentUser)
}

func TestIsAuthenticated(t *testing.T) {
	tests := []struct {
		name     string
		user     any
		expected bool
	}{
		{
			name:     "nil user",
			user:     nil,
			expected: false,
		},
		{
			name: "valid User pointer",
			user: &User{
				ID:   uuid.New(),
				Role: RoleAdmin,
			},
			expected: true,
		},
		{
			name: "valid User struct",
			user: User{
				ID:   uuid.New(),
				Role: RoleAdmin,
			},
			expected: true,
		},
		{
			name:     "nil User pointer",
			user:     (*User)(nil),
			expected: false,
		},
		{
			name: "JSON-converted user (non-empty map)",
			user: map[string]any{
				"id":        "123",
				"user_role": "admin",
			},
			expected: true,
		},
		{
			name:     "empty map",
			user:     map[string]any{},
			expected: false,
		},
		{
			name:     "invalid type",
			user:     "invalid",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAuthenticated(tt.user)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasRole(t *testing.T) {
	tests := []struct {
		name     string
		user     any
		role     string
		expected bool
	}{
		{
			name: "User pointer with matching role",
			user: &User{
				Role: RoleAdmin,
			},
			role:     "admin",
			expected: true,
		},
		{
			name: "User pointer with non-matching role",
			user: &User{
				Role: RoleAdmin,
			},
			role:     "member",
			expected: false,
		},
		{
			name: "User struct with matching role",
			user: User{
				Role: RoleMember,
			},
			role:     "member",
			expected: true,
		},
		{
			name:     "nil User pointer",
			user:     (*User)(nil),
			role:     "admin",
			expected: false,
		},
		{
			name: "JSON-converted user with matching role",
			user: map[string]any{
				"user_role": "admin",
			},
			role:     "admin",
			expected: true,
		},
		{
			name: "JSON-converted user with non-matching role",
			user: map[string]any{
				"user_role": "member",
			},
			role:     "admin",
			expected: false,
		},
		{
			name: "JSON-converted user without role field",
			user: map[string]any{
				"id": "123",
			},
			role:     "admin",
			expected: false,
		},
		{
			name:     "invalid user type",
			user:     "invalid",
			role:     "admin",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasRole(tt.user, tt.role)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsAtLeast(t *testing.T) {
	tests := []struct {
		name     string
		user     any
		minRole  string
		expected bool
	}{
		{
			name: "Admin user, admin min role",
			user: &User{
				Role: RoleAdmin,
			},
			minRole:  "admin",
			expected: true,
		},
		{
			name: "Admin user, member min role",
			user: &User{
				Role: RoleAdmin,
			},
			minRole:  "member",
			expected: true,
		},
		{
			name: "Member user, admin min role",
			user: &User{
				Role: RoleMember,
			},
			minRole:  "admin",
			expected: false,
		},
		{
			name: "Owner user, any role",
			user: &User{
				Role: RoleOwner,
			},
			minRole:  "guest",
			expected: true,
		},
		{
			name:     "nil user",
			user:     (*User)(nil),
			minRole:  "guest",
			expected: false,
		},
		{
			name: "JSON-converted admin user",
			user: map[string]any{
				"user_role": "admin",
			},
			minRole:  "member",
			expected: true,
		},
		{
			name:     "invalid user type",
			user:     "invalid",
			minRole:  "guest",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAtLeast(tt.user, tt.minRole)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCanRead(t *testing.T) {
	tests := []struct {
		name     string
		user     any
		expected bool
	}{
		{
			name: "Guest user can read",
			user: &User{
				Role: RoleGuest,
			},
			expected: true,
		},
		{
			name: "Member user can read",
			user: &User{
				Role: RoleMember,
			},
			expected: true,
		},
		{
			name: "Admin user can read",
			user: &User{
				Role: RoleAdmin,
			},
			expected: true,
		},
		{
			name: "Owner user can read",
			user: &User{
				Role: RoleOwner,
			},
			expected: true,
		},
		{
			name:     "nil user cannot read",
			user:     (*User)(nil),
			expected: false,
		},
		{
			name: "JSON-converted user can read",
			user: map[string]any{
				"user_role": "guest",
			},
			expected: true,
		},
		{
			name:     "invalid user type cannot read",
			user:     "invalid",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canRead(tt.user)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCanEdit(t *testing.T) {
	tests := []struct {
		name     string
		user     any
		expected bool
	}{
		{
			name: "Guest user cannot edit",
			user: &User{
				Role: RoleGuest,
			},
			expected: false,
		},
		{
			name: "Member user can edit",
			user: &User{
				Role: RoleMember,
			},
			expected: true,
		},
		{
			name: "Admin user can edit",
			user: &User{
				Role: RoleAdmin,
			},
			expected: true,
		},
		{
			name: "Owner user can edit",
			user: &User{
				Role: RoleOwner,
			},
			expected: true,
		},
		{
			name:     "nil user cannot edit",
			user:     (*User)(nil),
			expected: false,
		},
		{
			name: "JSON-converted member user can edit",
			user: map[string]any{
				"user_role": "member",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canEdit(tt.user)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCanCreate(t *testing.T) {
	tests := []struct {
		name     string
		user     any
		expected bool
	}{
		{
			name: "Guest user cannot create",
			user: &User{
				Role: RoleGuest,
			},
			expected: false,
		},
		{
			name: "Member user cannot create",
			user: &User{
				Role: RoleMember,
			},
			expected: false,
		},
		{
			name: "Admin user can create",
			user: &User{
				Role: RoleAdmin,
			},
			expected: true,
		},
		{
			name: "Owner user can create",
			user: &User{
				Role: RoleOwner,
			},
			expected: true,
		},
		{
			name:     "nil user cannot create",
			user:     (*User)(nil),
			expected: false,
		},
		{
			name: "JSON-converted admin user can create",
			user: map[string]any{
				"user_role": "admin",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canCreate(tt.user)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCanDelete(t *testing.T) {
	tests := []struct {
		name     string
		user     any
		expected bool
	}{
		{
			name: "Guest user cannot delete",
			user: &User{
				Role: RoleGuest,
			},
			expected: false,
		},
		{
			name: "Member user cannot delete",
			user: &User{
				Role: RoleMember,
			},
			expected: false,
		},
		{
			name: "Admin user cannot delete",
			user: &User{
				Role: RoleAdmin,
			},
			expected: false,
		},
		{
			name: "Owner user can delete",
			user: &User{
				Role: RoleOwner,
			},
			expected: true,
		},
		{
			name:     "nil user cannot delete",
			user:     (*User)(nil),
			expected: false,
		},
		{
			name: "JSON-converted owner user can delete",
			user: map[string]any{
				"user_role": "owner",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canDelete(tt.user)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCanAccess(t *testing.T) {
	adminUser := &User{Role: RoleAdmin}
	guestUser := &User{Role: RoleGuest}

	tests := []struct {
		name     string
		user     any
		action   string
		expected bool
	}{
		{
			name:     "admin can read",
			user:     adminUser,
			action:   "read",
			expected: true,
		},
		{
			name:     "admin can edit",
			user:     adminUser,
			action:   "edit",
			expected: true,
		},
		{
			name:     "admin can create",
			user:     adminUser,
			action:   "create",
			expected: true,
		},
		{
			name:     "admin cannot delete",
			user:     adminUser,
			action:   "delete",
			expected: false,
		},
		{
			name:     "guest can read",
			user:     guestUser,
			action:   "read",
			expected: true,
		},
		{
			name:     "guest cannot edit",
			user:     guestUser,
			action:   "edit",
			expected: false,
		},
		{
			name:     "invalid action returns false",
			user:     adminUser,
			action:   "invalid",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canAccess(tt.user, tt.action)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test that demonstrates the typical workflow
func TestTemplateHelpersWorkflow(t *testing.T) {
	// Create a user
	user := &User{
		ID:        uuid.New(),
		Role:      RoleAdmin,
		FirstName: "Jane",
		LastName:  "Smith",
		Username:  "janesmith",
		Email:     "jane@example.com",
	}

	// Get helpers with the user
	helpers := TemplateHelpersWithUser(user)

	// Test that we can check authentication
	isAuthFunc := helpers["is_authenticated"].(func(any) bool)
	assert.True(t, isAuthFunc(helpers["current_user"]))

	// Test that we can check roles
	hasRoleFunc := helpers["has_role"].(func(any, string) bool)
	assert.True(t, hasRoleFunc(helpers["current_user"], "admin"))
	assert.False(t, hasRoleFunc(helpers["current_user"], "owner"))

	// Test that we can check permissions
	canCreateFunc := helpers["can_create"].(func(any) bool)
	assert.True(t, canCreateFunc(helpers["current_user"]))

	canDeleteFunc := helpers["can_delete"].(func(any) bool)
	assert.False(t, canDeleteFunc(helpers["current_user"]))

	// Test role constants are available
	roles := helpers["roles"].(map[string]string)
	assert.Equal(t, "admin", roles["admin"])
}

func TestTemplateHelpersWithRouter(t *testing.T) {
	user := &User{
		ID:        uuid.New(),
		Role:      RoleAdmin,
		FirstName: "Jane",
		LastName:  "Doe",
		Username:  "janedoe",
		Email:     "jane@example.com",
		CreatedAt: &time.Time{},
	}

	tests := []struct {
		name     string
		setupCtx func() router.Context
		userKey  string
		wantUser bool
	}{
		{
			name: "should extract user with default key",
			setupCtx: func() router.Context {
				ctx := router.NewMockContext()
				ctx.LocalsMock["current_user"] = user
				return ctx
			},
			userKey:  "",
			wantUser: true,
		},
		{
			name: "should extract user with custom key",
			setupCtx: func() router.Context {
				ctx := router.NewMockContext()
				ctx.LocalsMock["template_user"] = user
				return ctx
			},
			userKey:  "template_user",
			wantUser: true,
		},
		{
			name: "should return helpers without user when not in context",
			setupCtx: func() router.Context {
				return router.NewMockContext()
			},
			userKey:  "current_user",
			wantUser: false,
		},
		{
			name: "should work with AuthClaims as user",
			setupCtx: func() router.Context {
				ctx := router.NewMockContext()
				claims := &JWTClaims{
					UID:      "user123",
					UserRole: "admin",
				}
				ctx.LocalsMock["current_user"] = claims
				return ctx
			},
			userKey:  "",
			wantUser: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			helpers := TemplateHelpersWithRouter(ctx, tt.userKey)

			// Test that all basic helpers are present
			assert.Contains(t, helpers, "is_authenticated")
			assert.Contains(t, helpers, "has_role")
			assert.Contains(t, helpers, "roles")

			if tt.wantUser {
				// Test that current_user is set
				assert.Contains(t, helpers, "current_user")
				assert.NotNil(t, helpers["current_user"])

				// Test that is_authenticated works with the injected user
				isAuthFunc := helpers["is_authenticated"].(func(any) bool)
				assert.True(t, isAuthFunc(helpers["current_user"]))
			} else {
				// User might be present but nil, or not present at all
				if currentUser, exists := helpers["current_user"]; exists {
					isAuthFunc := helpers["is_authenticated"].(func(any) bool)
					assert.False(t, isAuthFunc(currentUser))
				}
			}
		})
	}
}

func TestGetTemplateUser(t *testing.T) {
	user := &User{
		ID:       uuid.New(),
		Role:     RoleMember,
		Username: "testuser",
	}

	tests := []struct {
		name     string
		setupCtx func() router.Context
		userKey  string
		wantUser any
		wantOK   bool
	}{
		{
			name: "should return user with default key",
			setupCtx: func() router.Context {
				ctx := router.NewMockContext()
				ctx.LocalsMock["current_user"] = user
				return ctx
			},
			userKey:  "",
			wantUser: user,
			wantOK:   true,
		},
		{
			name: "should return user with custom key",
			setupCtx: func() router.Context {
				ctx := router.NewMockContext()
				ctx.LocalsMock["my_user"] = user
				return ctx
			},
			userKey:  "my_user",
			wantUser: user,
			wantOK:   true,
		},
		{
			name: "should return false when user not found",
			setupCtx: func() router.Context {
				return router.NewMockContext()
			},
			userKey:  "current_user",
			wantUser: nil,
			wantOK:   false,
		},
		{
			name: "should return false when user is nil",
			setupCtx: func() router.Context {
				ctx := router.NewMockContext()
				ctx.LocalsMock["current_user"] = nil
				return ctx
			},
			userKey:  "",
			wantUser: nil,
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			gotUser, gotOK := GetTemplateUser(ctx, tt.userKey)

			assert.Equal(t, tt.wantOK, gotOK)
			assert.Equal(t, tt.wantUser, gotUser)
		})
	}
}

// Test the full integration workflow
func TestTemplateIntegrationWorkflow(t *testing.T) {
	// Simulate middleware storing user in context
	user := &User{
		ID:        uuid.New(),
		Role:      RoleAdmin,
		FirstName: "Integration",
		LastName:  "Test",
		Username:  "integrationtest",
		Email:     "integration@test.com",
	}

	// Create mock context as middleware would
	ctx := router.NewMockContext()
	ctx.LocalsMock["current_user"] = user

	// Extract user using helper function
	templateUser, ok := GetTemplateUser(ctx, "current_user")
	require.True(t, ok, "Should find user in context")
	require.Equal(t, user, templateUser)

	// Get helpers with router context
	helpers := TemplateHelpersWithRouter(ctx, "current_user")

	// Verify user is available in helpers
	require.Contains(t, helpers, "current_user")
	assert.Equal(t, user, helpers["current_user"])

	// Test template functions work with injected user
	isAuthFunc := helpers["is_authenticated"].(func(any) bool)
	assert.True(t, isAuthFunc(helpers["current_user"]))

	hasRoleFunc := helpers["has_role"].(func(any, string) bool)
	assert.True(t, hasRoleFunc(helpers["current_user"], "admin"))
	assert.False(t, hasRoleFunc(helpers["current_user"], "owner"))

	canCreateFunc := helpers["can_create"].(func(any) bool)
	assert.True(t, canCreateFunc(helpers["current_user"]))

	canDeleteFunc := helpers["can_delete"].(func(any) bool)
	assert.False(t, canDeleteFunc(helpers["current_user"]))
}
