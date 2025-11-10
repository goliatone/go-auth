package auth

import (
	"context"
	"testing"
	"time"

	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock TokenService for testing
type mockTokenService struct {
	mock.Mock
}

func (m *mockTokenService) Generate(identity Identity, resourceRoles map[string]string) (string, error) {
	args := m.Called(identity, resourceRoles)
	return args.String(0), args.Error(1)
}

func (m *mockTokenService) SignClaims(claims *JWTClaims) (string, error) {
	args := m.Called(claims)
	return args.String(0), args.Error(1)
}

func (m *mockTokenService) Validate(tokenString string) (AuthClaims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(AuthClaims), args.Error(1)
}

// Mock AuthClaims for testing
type mockAuthClaims struct {
	mock.Mock
}

func (m *mockAuthClaims) Subject() string {
	return m.Called().String(0)
}

func (m *mockAuthClaims) UserID() string {
	return m.Called().String(0)
}

func (m *mockAuthClaims) Role() string {
	return m.Called().String(0)
}

func (m *mockAuthClaims) CanRead(resource string) bool {
	return m.Called(resource).Bool(0)
}

func (m *mockAuthClaims) CanEdit(resource string) bool {
	return m.Called(resource).Bool(0)
}

func (m *mockAuthClaims) CanCreate(resource string) bool {
	return m.Called(resource).Bool(0)
}

func (m *mockAuthClaims) CanDelete(resource string) bool {
	return m.Called(resource).Bool(0)
}

func (m *mockAuthClaims) HasRole(role string) bool {
	return m.Called(role).Bool(0)
}

func (m *mockAuthClaims) IsAtLeast(minRole string) bool {
	return m.Called(minRole).Bool(0)
}

func (m *mockAuthClaims) Expires() time.Time {
	return m.Called().Get(0).(time.Time)
}

func (m *mockAuthClaims) IssuedAt() time.Time {
	return m.Called().Get(0).(time.Time)
}

func TestWSTokenValidator_Validate(t *testing.T) {
	// Setup
	mockTokenSvc := &mockTokenService{}
	mockClaims := &mockAuthClaims{}
	validator := NewWSTokenValidator(mockTokenSvc)

	// Test successful validation
	t.Run("successful validation", func(t *testing.T) {
		token := "valid-token"

		mockTokenSvc.On("Validate", token).Return(mockClaims, nil)

		result, err := validator.Validate(token)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.IsType(t, &WSAuthClaimsAdapter{}, result)

		// Verify the adapter wraps the original claims
		adapter := result.(*WSAuthClaimsAdapter)
		assert.Equal(t, mockClaims, adapter.claims)

		mockTokenSvc.AssertExpectations(t)
	})

	// Test validation error
	t.Run("validation error", func(t *testing.T) {
		token := "invalid-token"
		expectedErr := ErrTokenMalformed

		mockTokenSvc.On("Validate", token).Return(nil, expectedErr)

		result, err := validator.Validate(token)

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.Nil(t, result)

		mockTokenSvc.AssertExpectations(t)
	})
}

func TestWSAuthClaimsAdapter(t *testing.T) {
	// Setup
	mockClaims := &mockAuthClaims{}
	adapter := &WSAuthClaimsAdapter{claims: mockClaims}

	// Test all methods delegate correctly
	t.Run("Subject", func(t *testing.T) {
		expected := "user123"
		mockClaims.On("Subject").Return(expected)

		result := adapter.Subject()

		assert.Equal(t, expected, result)
		mockClaims.AssertExpectations(t)
	})

	t.Run("UserID", func(t *testing.T) {
		expected := "user123"
		mockClaims.On("UserID").Return(expected)

		result := adapter.UserID()

		assert.Equal(t, expected, result)
		mockClaims.AssertExpectations(t)
	})

	t.Run("Role", func(t *testing.T) {
		expected := "admin"
		mockClaims.On("Role").Return(expected)

		result := adapter.Role()

		assert.Equal(t, expected, result)
		mockClaims.AssertExpectations(t)
	})

	t.Run("CanRead", func(t *testing.T) {
		resource := "posts"
		expected := true
		mockClaims.On("CanRead", resource).Return(expected)

		result := adapter.CanRead(resource)

		assert.Equal(t, expected, result)
		mockClaims.AssertExpectations(t)
	})

	t.Run("CanEdit", func(t *testing.T) {
		resource := "posts"
		expected := false
		mockClaims.On("CanEdit", resource).Return(expected)

		result := adapter.CanEdit(resource)

		assert.Equal(t, expected, result)
		mockClaims.AssertExpectations(t)
	})

	t.Run("CanCreate", func(t *testing.T) {
		resource := "posts"
		expected := true
		mockClaims.On("CanCreate", resource).Return(expected)

		result := adapter.CanCreate(resource)

		assert.Equal(t, expected, result)
		mockClaims.AssertExpectations(t)
	})

	t.Run("CanDelete", func(t *testing.T) {
		resource := "posts"
		expected := false
		mockClaims.On("CanDelete", resource).Return(expected)

		result := adapter.CanDelete(resource)

		assert.Equal(t, expected, result)
		mockClaims.AssertExpectations(t)
	})

	t.Run("HasRole", func(t *testing.T) {
		role := "admin"
		expected := true
		mockClaims.On("HasRole", role).Return(expected)

		result := adapter.HasRole(role)

		assert.Equal(t, expected, result)
		mockClaims.AssertExpectations(t)
	})

	t.Run("IsAtLeast", func(t *testing.T) {
		minRole := "user"
		expected := true
		mockClaims.On("IsAtLeast", minRole).Return(expected)

		result := adapter.IsAtLeast(minRole)

		assert.Equal(t, expected, result)
		mockClaims.AssertExpectations(t)
	})
}

type otherClaims struct{}

func (o *otherClaims) Subject() string                { return "other" }
func (o *otherClaims) UserID() string                 { return "other" }
func (o *otherClaims) Role() string                   { return "other" }
func (o *otherClaims) CanRead(resource string) bool   { return false }
func (o *otherClaims) CanEdit(resource string) bool   { return false }
func (o *otherClaims) CanCreate(resource string) bool { return false }
func (o *otherClaims) CanDelete(resource string) bool { return false }
func (o *otherClaims) HasRole(role string) bool       { return false }
func (o *otherClaims) IsAtLeast(minRole string) bool  { return false }

func TestWSAuthClaimsFromContext(t *testing.T) {
	// Test with go-auth claims in context
	t.Run("with go-auth claims", func(t *testing.T) {
		mockClaims := &mockAuthClaims{}
		adapter := &WSAuthClaimsAdapter{claims: mockClaims}

		// Put adapter in context using go-router's context key
		ctx := context.WithValue(context.Background(), router.WSAuthContextKey{}, adapter)

		result, ok := WSAuthClaimsFromContext(ctx)

		assert.True(t, ok)
		assert.Equal(t, mockClaims, result)
	})

	// Test with no claims in context
	t.Run("no claims in context", func(t *testing.T) {
		ctx := context.Background()

		result, ok := WSAuthClaimsFromContext(ctx)

		assert.False(t, ok)
		assert.Nil(t, result)
	})

	// Test with non-go-auth claims in context
	t.Run("non go-auth claims", func(t *testing.T) {
		// Simulate some other implementation of WSAuthClaims

		other := &otherClaims{}
		ctx := context.WithValue(context.Background(), router.WSAuthContextKey{}, other)

		result, ok := WSAuthClaimsFromContext(ctx)

		assert.False(t, ok)
		assert.Nil(t, result)
	})
}
