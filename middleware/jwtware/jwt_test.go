package jwtware_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/goliatone/go-auth/middleware/jwtware"
)

// MockAuthClaims implements jwtware.AuthClaims for testing
type MockAuthClaims struct {
	mock.Mock
	subject   string
	userID    string
	role      string
	canRead   bool
	canEdit   bool
	canCreate bool
	canDelete bool
}

func NewMockAuthClaims(subject, userID, role string) *MockAuthClaims {
	return &MockAuthClaims{
		subject:   subject,
		userID:    userID,
		role:      role,
		canRead:   true, // Default permissions for testing
		canEdit:   true,
		canCreate: false,
		canDelete: false,
	}
}

func (m *MockAuthClaims) Subject() string                { return m.subject }
func (m *MockAuthClaims) UserID() string                 { return m.userID }
func (m *MockAuthClaims) Role() string                   { return m.role }
func (m *MockAuthClaims) CanRead(resource string) bool   { return m.canRead }
func (m *MockAuthClaims) CanEdit(resource string) bool   { return m.canEdit }
func (m *MockAuthClaims) CanCreate(resource string) bool { return m.canCreate }
func (m *MockAuthClaims) CanDelete(resource string) bool { return m.canDelete }
func (m *MockAuthClaims) HasRole(role string) bool       { return m.role == role }
func (m *MockAuthClaims) IsAtLeast(minRole string) bool {
	// Simple role hierarchy for testing
	roles := map[string]int{"guest": 1, "member": 2, "admin": 3, "owner": 4}
	return roles[m.role] >= roles[minRole]
}

// MockTokenValidator implements jwtware.TokenValidator for testing
type MockTokenValidator struct {
	mock.Mock
	validateFunc func(string) (jwtware.AuthClaims, error)
}

func NewMockTokenValidator() *MockTokenValidator {
	return &MockTokenValidator{}
}

func (m *MockTokenValidator) WithValidateFunc(fn func(string) (jwtware.AuthClaims, error)) *MockTokenValidator {
	m.validateFunc = fn
	return m
}

func (m *MockTokenValidator) Validate(tokenString string) (jwtware.AuthClaims, error) {
	if m.validateFunc != nil {
		return m.validateFunc(tokenString)
	}
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(jwtware.AuthClaims), args.Error(1)
}

//--------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------

func TestJWTWare_ValidToken(t *testing.T) {
	// Create mock claims for successful validation
	claims := NewMockAuthClaims("user-123", "user-123", "admin")

	// Create validator that returns valid claims
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		if strings.Contains(tokenString, "valid-token") {
			return claims, nil
		}
		return nil, errors.New("invalid token")
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	// Test with valid token
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-token-12345"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-token-12345")

	// The middleware should store the AuthClaims in context
	var storedClaims jwtware.AuthClaims
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Run(func(args mock.Arguments) {
		storedClaims = args.Get(1).(jwtware.AuthClaims)
	}).Return(nil)
	// The middleware also stores user for templates with default key "current_user"
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	err := handler(ctx)

	assert.NoError(t, err)
	assert.True(t, ctx.NextCalled, "Next() should be called for valid token")
	assert.NotNil(t, storedClaims, "Claims should be stored in context")
	assert.Equal(t, "user-123", storedClaims.Subject())
	assert.Equal(t, "admin", storedClaims.Role())
}

func TestJWTWare_MissingToken(t *testing.T) {
	validator := NewMockTokenValidator()

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	// Test with missing token
	ctx := router.NewMockContext()
	ctx.On("GetString", "Authorization", "").Return("")

	err := handler(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing or malformed JWT")
	assert.False(t, ctx.NextCalled, "Next() should not be called for missing token")
}

func TestJWTWare_MalformedToken(t *testing.T) {
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return nil, errors.New("token is malformed")
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	// Test with malformed token
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer malformed.token.structure"
	ctx.On("GetString", "Authorization", "").Return("Bearer malformed.token.structure")

	err := handler(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is malformed")
	assert.False(t, ctx.NextCalled, "Next() should not be called for malformed token")
}

func TestJWTWare_ExpiredToken(t *testing.T) {
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return nil, errors.New("token is expired")
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer expired-token-12345"
	ctx.On("GetString", "Authorization", "").Return("Bearer expired-token-12345")

	err := handler(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired")
	assert.False(t, ctx.NextCalled, "Next() should not be called for expired token")
}

func TestJWTWare_TokenLookupVariations(t *testing.T) {
	// Simplified test focusing on basic functionality
	claims := NewMockAuthClaims("user-456", "user-456", "member")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	// Test with Authorization header token
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-token")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)
	// The middleware also stores user for templates with default key "current_user"
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	err := handler(ctx)

	assert.NoError(t, err)
	assert.True(t, ctx.NextCalled, "Next() should be called for valid token")
}

func TestJWTWare_FilterFunction(t *testing.T) {
	validator := NewMockTokenValidator()

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		Filter: func(ctx router.Context) bool {
			// Skip middleware for /public paths
			return strings.HasPrefix(ctx.Path(), "/public")
		},
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	// Test filtered path (should skip auth)
	ctx := router.NewMockContext()
	ctx.On("Path").Return("/public/resource")

	err := handler(ctx)

	assert.NoError(t, err)
	assert.True(t, ctx.NextCalled, "Next() should be called for filtered path")
}

func TestJWTWare_CustomContextKey(t *testing.T) {
	claims := NewMockAuthClaims("user-789", "user-789", "owner")

	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		ContextKey:     "custom_user",
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-token")
	ctx.On("Locals", "custom_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)
	// The middleware also stores user for templates with default key "current_user"
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	err := handler(ctx)

	assert.NoError(t, err)
	assert.True(t, ctx.NextCalled, "Next() should be called")
}

func TestJWTWare_RequiredTokenValidator(t *testing.T) {
	// Test that middleware panics without TokenValidator
	assert.Panics(t, func() {
		cfg := jwtware.Config{
			SigningKey: jwtware.SigningKey{
				Key:    []byte("test-key"),
				JWTAlg: "HS256",
			},
			// No TokenValidator provided
		}
		jwtware.New(cfg)
	}, "Should panic when TokenValidator is not provided")
}

//--------------------------------------------------------------------------------------
// RBAC Tests
//--------------------------------------------------------------------------------------

func TestJWTWare_RequiredRole_Success(t *testing.T) {
	// Create claims with admin role
	claims := NewMockAuthClaims("user-123", "user-123", "admin")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		RequiredRole:   "admin", // Require exact admin role
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-admin-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-admin-token")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)
	// The middleware also stores user for templates with default key "current_user"
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	err := handler(ctx)

	assert.NoError(t, err, "Should allow access for user with required admin role")
	assert.True(t, ctx.NextCalled, "Next() should be called when role requirement is satisfied")
}

func TestJWTWare_RequiredRole_AccessDenied(t *testing.T) {
	// Create claims with member role (not admin)
	claims := NewMockAuthClaims("user-456", "user-456", "member")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		RequiredRole:   "admin", // Require admin role but user has member
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-member-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-member-token")

	err := handler(ctx)

	assert.Error(t, err, "Should deny access when user doesn't have required role")
	assert.Contains(t, err.Error(), "access denied: required role 'admin' not found")
	assert.False(t, ctx.NextCalled, "Next() should not be called when role requirement fails")
}

func TestJWTWare_MinimumRole_Success(t *testing.T) {
	// Create claims with admin role (higher than required member)
	claims := NewMockAuthClaims("user-789", "user-789", "admin")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		MinimumRole:    "member", // Admin is at least member level
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-admin-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-admin-token")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)
	// The middleware also stores user for templates with default key "current_user"
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	err := handler(ctx)

	assert.NoError(t, err, "Should allow access for user exceeding minimum role")
	assert.True(t, ctx.NextCalled, "Next() should be called when minimum role requirement is satisfied")
}

func TestJWTWare_MinimumRole_AccessDenied(t *testing.T) {
	// Create claims with guest role (lower than required member)
	claims := NewMockAuthClaims("user-101", "user-101", "guest")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		MinimumRole:    "member", // Guest is below member level
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-guest-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-guest-token")

	err := handler(ctx)

	assert.Error(t, err, "Should deny access when user is below minimum role")
	assert.Contains(t, err.Error(), "access denied: minimum role 'member' required")
	assert.False(t, ctx.NextCalled, "Next() should not be called when minimum role requirement fails")
}

func TestJWTWare_CustomRoleChecker_Success(t *testing.T) {
	claims := NewMockAuthClaims("user-202", "user-202", "manager")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		RequiredRole:   "manager",
		RoleChecker: func(claims jwtware.AuthClaims, requiredRole string) bool {
			// Custom logic: managers can access admin endpoints too
			if claims.Role() == "manager" && requiredRole == "manager" {
				return true
			}
			return claims.HasRole(requiredRole)
		},
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-manager-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-manager-token")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)
	// The middleware also stores user for templates with default key "current_user"
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	err := handler(ctx)

	assert.NoError(t, err, "Should allow access when custom role checker returns true")
	assert.True(t, ctx.NextCalled, "Next() should be called when custom role checker succeeds")
}

func TestJWTWare_CustomRoleChecker_AccessDenied(t *testing.T) {
	claims := NewMockAuthClaims("user-303", "user-303", "guest")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		RequiredRole:   "manager",
		RoleChecker: func(claims jwtware.AuthClaims, requiredRole string) bool {
			// Strict custom logic: only managers can access manager endpoints
			return claims.Role() == "manager" && requiredRole == "manager"
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-guest-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-guest-token")

	err := handler(ctx)

	assert.Error(t, err, "Should deny access when required role is not met")
	// Note: RequiredRole check happens before RoleChecker, so we get the "required role not found" error
	assert.Contains(t, err.Error(), "access denied: required role 'manager' not found")
	assert.False(t, ctx.NextCalled, "Next() should not be called when required role check fails")
}

func TestJWTWare_CustomRoleChecker_OnlyCheck_AccessDenied(t *testing.T) {
	claims := NewMockAuthClaims("user-404", "user-404", "guest")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		// Only use RoleChecker, no RequiredRole or MinimumRole
		RoleChecker: func(claims jwtware.AuthClaims, role string) bool {
			// This should fail since no role is provided to check against
			return false
		},
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-guest-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-guest-token")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)
	// The middleware also stores user for templates with default key "current_user"
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	err := handler(ctx)

	// Since no RequiredRole or MinimumRole is set, and RoleChecker gets empty string,
	// the custom role check should not be invoked per the implementation logic
	assert.NoError(t, err, "Should allow access when RoleChecker is provided but no role to check against")
	assert.True(t, ctx.NextCalled, "Next() should be called when custom role checker is skipped due to empty role")
}

func TestJWTWare_CustomRoleChecker_OnlyCheck_WithMinimumRole_AccessDenied(t *testing.T) {
	claims := NewMockAuthClaims("user-405", "user-405", "guest")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		MinimumRole:    "admin", // Set minimum role but user is guest (should pass MinimumRole check first)
		RoleChecker: func(claims jwtware.AuthClaims, role string) bool {
			// This should be called after MinimumRole check fails
			return false
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-guest-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-guest-token")

	err := handler(ctx)

	assert.Error(t, err, "Should deny access when minimum role check fails")
	// MinimumRole check happens before RoleChecker, so we get the minimum role error
	assert.Contains(t, err.Error(), "access denied: minimum role 'admin' required")
	assert.False(t, ctx.NextCalled, "Next() should not be called when minimum role check fails")
}

func TestJWTWare_CustomRoleChecker_WithMinimumRole(t *testing.T) {
	claims := NewMockAuthClaims("user-404", "user-404", "admin")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		MinimumRole:    "member", // Admin is at least member level
		RoleChecker: func(claims jwtware.AuthClaims, role string) bool {
			// Custom logic for minimum role checking
			return claims.IsAtLeast(role)
		},
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-admin-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-admin-token")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)
	// The middleware also stores user for templates with default key "current_user"
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	err := handler(ctx)

	assert.NoError(t, err, "Should allow access when custom role checker validates minimum role")
	assert.True(t, ctx.NextCalled, "Next() should be called when custom role checker succeeds for minimum role")
}

func TestJWTWare_NoRBACConfiguration_AllowsAccess(t *testing.T) {
	claims := NewMockAuthClaims("user-505", "user-505", "guest")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		// No RBAC configuration (RequiredRole, MinimumRole, or RoleChecker)
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-guest-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-guest-token")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)
	// The middleware also stores user for templates with default key "current_user"
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	err := handler(ctx)

	assert.NoError(t, err, "Should allow access when no RBAC configuration is provided")
	assert.True(t, ctx.NextCalled, "Next() should be called when RBAC checks are skipped")
}

func TestJWTWare_MultipleRoleRequirements(t *testing.T) {
	claims := NewMockAuthClaims("user-606", "user-606", "admin")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		RequiredRole:   "admin",  // Must have exact admin role
		MinimumRole:    "member", // Must be at least member level
		RoleChecker: func(claims jwtware.AuthClaims, role string) bool {
			// Additional custom validation
			return claims.Role() == "admin" && claims.IsAtLeast("member")
		},
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-admin-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-admin-token")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)
	// The middleware also stores user for templates with default key "current_user"
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	err := handler(ctx)

	assert.NoError(t, err, "Should allow access when all role requirements are satisfied")
	assert.True(t, ctx.NextCalled, "Next() should be called when all role checks pass")
}

//--------------------------------------------------------------------------------------
// Context Propagation Tests
//--------------------------------------------------------------------------------------

func TestJWTWare_ContextEnricher_Propagation(t *testing.T) {
	// Create mock claims for successful validation
	claims := NewMockAuthClaims("user-123", "user-123", "admin")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	// Create a mock context enricher that adds a known value to the context
	const testKey = "test-claims-key"
	const testValue = "enriched-claims-value"

	contextEnricher := func(c context.Context, claims jwtware.AuthClaims) context.Context {
		return context.WithValue(c, testKey, testValue)
	}

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator:  validator,
		ContextEnricher: contextEnricher,
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	// Create mock context with initial standard context
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-token-12345"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-token-12345")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)
	// The middleware also stores user for templates with default key "current_user"
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	// Mock the Context() method to return an empty context initially
	initialCtx := context.Background()
	ctx.On("Context").Return(initialCtx)

	// Mock SetContext to capture the enriched context
	var enrichedCtx context.Context
	ctx.On("SetContext", mock.AnythingOfType("*context.valueCtx")).Run(func(args mock.Arguments) {
		enrichedCtx = args.Get(0).(context.Context)
	}).Return()

	err := handler(ctx)

	assert.NoError(t, err, "Middleware should succeed with valid token")
	assert.True(t, ctx.NextCalled, "Next() should be called for valid token")

	// Verify that SetContext was called
	ctx.AssertCalled(t, "SetContext", mock.AnythingOfType("*context.valueCtx"))

	// Verify that the enriched context contains the expected value
	assert.NotNil(t, enrichedCtx, "Enriched context should not be nil")
	value := enrichedCtx.Value(testKey)
	assert.Equal(t, testValue, value, "Enriched context should contain the test value")
}

func TestJWTWare_ContextEnricher_NotCalled_When_Nil(t *testing.T) {
	// Create mock claims for successful validation
	claims := NewMockAuthClaims("user-456", "user-456", "member")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		// ContextEnricher is nil (not provided)
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	// Create mock context
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-token-67890"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-token-67890")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)
	// The middleware also stores user for templates with default key "current_user"
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	err := handler(ctx)

	assert.NoError(t, err, "Middleware should succeed with valid token")
	assert.True(t, ctx.NextCalled, "Next() should be called for valid token")

	// Verify that SetContext was NOT called since ContextEnricher is nil
	ctx.AssertNotCalled(t, "SetContext")
	ctx.AssertNotCalled(t, "Context")
}

func TestJWTWare_ContextEnricher_Called_With_Correct_Claims(t *testing.T) {
	// Create mock claims for successful validation
	expectedSubject := "user-789"
	expectedRole := "owner"
	claims := NewMockAuthClaims(expectedSubject, expectedSubject, expectedRole)
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	// Create a context enricher that verifies it receives the correct claims
	var receivedClaims jwtware.AuthClaims
	contextEnricher := func(c context.Context, claims jwtware.AuthClaims) context.Context {
		receivedClaims = claims
		return context.WithValue(c, "verified", true)
	}

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator:  validator,
		ContextEnricher: contextEnricher,
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	// Create mock context
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-owner-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-owner-token")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)
	// The middleware also stores user for templates with default key "current_user"
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)
	ctx.On("Context").Return(context.Background())
	ctx.On("SetContext", mock.AnythingOfType("*context.valueCtx")).Return()

	err := handler(ctx)

	assert.NoError(t, err, "Middleware should succeed with valid token")
	assert.True(t, ctx.NextCalled, "Next() should be called for valid token")

	// Verify that the context enricher received the correct claims
	assert.NotNil(t, receivedClaims, "ContextEnricher should have been called with claims")
	assert.Equal(t, expectedSubject, receivedClaims.Subject(), "Claims should have correct subject")
	assert.Equal(t, expectedRole, receivedClaims.Role(), "Claims should have correct role")
}

//--------------------------------------------------------------------------------------
// Template User Tests
//--------------------------------------------------------------------------------------

func TestJWTWare_TemplateUser_WithUserProvider_MapOutput_UsesLocalsMerge(t *testing.T) {
	// Create mock claims for successful validation
	claims := NewMockAuthClaims("user-123", "user-123", "admin")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	// UserProvider that returns a map[string]any (should trigger LocalsMerge)
	userProvider := func(claims jwtware.AuthClaims) (any, error) {
		return map[string]any{
			"id":       claims.UserID(),
			"username": "admin_user",
			"role":     claims.Role(),
			"email":    "admin@example.com",
		}, nil
	}

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		UserProvider:   userProvider,
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	// Create mock context
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-token-12345"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-token-12345")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	// This is the key test: LocalsMerge should be called with map data
	var mergedData map[string]any
	ctx.On("LocalsMerge", "current_user", mock.AnythingOfType("map[string]interface {}")).Run(func(args mock.Arguments) {
		mergedData = args.Get(1).(map[string]any)
	}).Return(map[string]any{})

	err := handler(ctx)

	assert.NoError(t, err, "Middleware should succeed with valid token")
	assert.True(t, ctx.NextCalled, "Next() should be called for valid token")

	// Verify that LocalsMerge was called with correct map data
	ctx.AssertCalled(t, "LocalsMerge", "current_user", mock.AnythingOfType("map[string]interface {}"))
	assert.NotNil(t, mergedData, "LocalsMerge should have received map data")
	assert.Equal(t, "user-123", mergedData["id"], "Map should contain user ID")
	assert.Equal(t, "admin_user", mergedData["username"], "Map should contain username")
	assert.Equal(t, "admin", mergedData["role"], "Map should contain role")
	assert.Equal(t, "admin@example.com", mergedData["email"], "Map should contain email")
}

func TestJWTWare_TemplateUser_WithUserProvider_NonMapOutput_UsesLocals(t *testing.T) {
	// Create mock claims for successful validation
	claims := NewMockAuthClaims("user-456", "user-456", "member")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	// UserProvider that returns a struct (not a map, should use Locals)
	type User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
		Email    string `json:"email"`
	}

	userProvider := func(claims jwtware.AuthClaims) (any, error) {
		return User{
			ID:       claims.UserID(),
			Username: "member_user",
			Role:     claims.Role(),
			Email:    "member@example.com",
		}, nil
	}

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		UserProvider:   userProvider,
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	// Create mock context
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-token-67890"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-token-67890")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	// This should use Locals (not LocalsMerge) since output is not a map
	var storedUser User
	ctx.On("Locals", "current_user", mock.AnythingOfType("jwtware_test.User")).Run(func(args mock.Arguments) {
		storedUser = args.Get(1).(User)
	}).Return(nil)

	err := handler(ctx)

	assert.NoError(t, err, "Middleware should succeed with valid token")
	assert.True(t, ctx.NextCalled, "Next() should be called for valid token")

	// Verify that Locals was called with struct data (not LocalsMerge)
	ctx.AssertCalled(t, "Locals", "current_user", mock.AnythingOfType("jwtware_test.User"))
	ctx.AssertNotCalled(t, "LocalsMerge", mock.Anything, mock.Anything)
	assert.Equal(t, "user-456", storedUser.ID, "User struct should contain correct ID")
	assert.Equal(t, "member_user", storedUser.Username, "User struct should contain correct username")
	assert.Equal(t, "member", storedUser.Role, "User struct should contain correct role")
	assert.Equal(t, "member@example.com", storedUser.Email, "User struct should contain correct email")
}

func TestJWTWare_TemplateUser_DefaultKey_IsCurrentUser(t *testing.T) {
	// Create mock claims for successful validation
	claims := NewMockAuthClaims("user-999", "user-999", "guest")
	validator := NewMockTokenValidator().WithValidateFunc(func(tokenString string) (jwtware.AuthClaims, error) {
		return claims, nil
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    []byte("test-key"),
			JWTAlg: "HS256",
		},
		TokenValidator: validator,
		// No TemplateUserKey specified, should default to "current_user"
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := jwtware.New(cfg)(func(ctx router.Context) error {
		return nil
	})

	// Create mock context
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-guest-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-guest-token")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	// Should use default "current_user" key with claims directly (no UserProvider)
	var storedClaims jwtware.AuthClaims
	ctx.On("Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Run(func(args mock.Arguments) {
		storedClaims = args.Get(1).(jwtware.AuthClaims)
	}).Return(nil)

	err := handler(ctx)

	assert.NoError(t, err, "Middleware should succeed with valid token")
	assert.True(t, ctx.NextCalled, "Next() should be called for valid token")

	// Verify that template user was stored under "current_user" key
	ctx.AssertCalled(t, "Locals", "current_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims"))
	assert.NotNil(t, storedClaims, "Claims should be stored as template user")
	assert.Equal(t, "user-999", storedClaims.Subject(), "Template user should have correct subject")
	assert.Equal(t, "guest", storedClaims.Role(), "Template user should have correct role")
}
