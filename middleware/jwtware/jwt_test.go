package jwtware_test

import (
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

	middleware := jwtware.New(cfg)

	// Test with valid token
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-token-12345"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-token-12345")

	// The middleware should store the AuthClaims in context
	var storedClaims jwtware.AuthClaims
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Run(func(args mock.Arguments) {
		storedClaims = args.Get(1).(jwtware.AuthClaims)
	}).Return(nil)

	err := middleware(ctx)

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

	middleware := jwtware.New(cfg)

	// Test with missing token
	ctx := router.NewMockContext()
	ctx.On("GetString", "Authorization", "").Return("")

	err := middleware(ctx)

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

	middleware := jwtware.New(cfg)

	// Test with malformed token
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer malformed.token.structure"
	ctx.On("GetString", "Authorization", "").Return("Bearer malformed.token.structure")

	err := middleware(ctx)

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

	middleware := jwtware.New(cfg)

	// Test with expired token
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer expired-token-12345"
	ctx.On("GetString", "Authorization", "").Return("Bearer expired-token-12345")

	err := middleware(ctx)

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

	middleware := jwtware.New(cfg)

	// Test with Authorization header token
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-token")
	ctx.On("Locals", "user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	err := middleware(ctx)

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

	middleware := jwtware.New(cfg)

	// Test filtered path (should skip auth)
	ctx := router.NewMockContext()
	ctx.On("Path").Return("/public/resource")

	err := middleware(ctx)

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

	middleware := jwtware.New(cfg)

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer valid-token"
	ctx.On("GetString", "Authorization", "").Return("Bearer valid-token")
	ctx.On("Locals", "custom_user", mock.AnythingOfType("*jwtware_test.MockAuthClaims")).Return(nil)

	err := middleware(ctx)

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
