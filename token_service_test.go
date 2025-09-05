package auth_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockIdentity implements auth.Identity for testing
type MockIdentity struct {
	mock.Mock
}

func (m *MockIdentity) ID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockIdentity) Username() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockIdentity) Email() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockIdentity) Role() string {
	args := m.Called()
	return args.String(0)
}

// MockLogger implements auth.Logger for testing
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Debug(format string, args ...any) {
	m.Called(format, args)
}

func (m *MockLogger) Info(format string, args ...any) {
	m.Called(format, args)
}

func (m *MockLogger) Warn(format string, args ...any) {
	m.Called(format, args)
}

func (m *MockLogger) Error(format string, args ...any) {
	m.Called(format, args)
}

func TestNewTokenService(t *testing.T) {
	signingKey := []byte("test-signing-key")
	tokenExpiration := 24
	issuer := "test-issuer"
	audience := jwt.ClaimStrings{"test-audience"}

	t.Run("creates token service with logger", func(t *testing.T) {
		logger := &MockLogger{}

		service := auth.NewTokenService(signingKey, tokenExpiration, issuer, audience, logger)

		assert.NotNil(t, service)
	})

	t.Run("creates token service with nil logger", func(t *testing.T) {
		service := auth.NewTokenService(signingKey, tokenExpiration, issuer, audience, nil)

		assert.NotNil(t, service)
	})
}

func TestTokenService_Generate(t *testing.T) {
	signingKey := []byte("test-signing-key")
	tokenExpiration := 24
	issuer := "test-issuer"
	audience := jwt.ClaimStrings{"test-audience"}
	logger := &MockLogger{}

	service := auth.NewTokenService(signingKey, tokenExpiration, issuer, audience, logger)

	t.Run("generates valid JWT token", func(t *testing.T) {
		identity := &MockIdentity{}
		identity.On("ID").Return("user-123")
		identity.On("Role").Return("admin")

		tokenString, err := service.Generate(identity)

		assert.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Parse the token to verify structure
		token, err := jwt.ParseWithClaims(tokenString, &auth.JWTClaims{}, func(token *jwt.Token) (any, error) {
			return signingKey, nil
		})

		assert.NoError(t, err)
		assert.True(t, token.Valid)

		claims, ok := token.Claims.(*auth.JWTClaims)
		assert.True(t, ok)
		assert.Equal(t, "user-123", claims.Subject())
		assert.Equal(t, "user-123", claims.UserID())
		assert.Equal(t, "admin", claims.Role())
		assert.Equal(t, issuer, claims.Issuer)
		assert.Equal(t, audience, claims.Audience)
		assert.NotNil(t, claims.IssuedAt)
		assert.NotNil(t, claims.ExpiresAt)
		assert.NotNil(t, claims.Resources)
		assert.Empty(t, claims.Resources) // Should be empty for basic generation

		identity.AssertExpectations(t)
	})

	t.Run("sets correct expiration time", func(t *testing.T) {
		identity := &MockIdentity{}
		identity.On("ID").Return("user-123")
		identity.On("Role").Return("member")

		beforeGenerate := time.Now()
		tokenString, err := service.Generate(identity)
		afterGenerate := time.Now()

		assert.NoError(t, err)

		token, err := jwt.ParseWithClaims(tokenString, &auth.JWTClaims{}, func(token *jwt.Token) (any, error) {
			return signingKey, nil
		})

		assert.NoError(t, err)
		claims := token.Claims.(*auth.JWTClaims)

		expectedExpiry := beforeGenerate.Add(time.Duration(tokenExpiration) * time.Hour)
		actualExpiry := claims.ExpiresAt.Time

		// Allow for a small margin of difference due to timing
		assert.True(t, actualExpiry.After(expectedExpiry.Add(-time.Second)))
		assert.True(t, actualExpiry.Before(afterGenerate.Add(time.Duration(tokenExpiration)*time.Hour+time.Second)))

		identity.AssertExpectations(t)
	})
}

func TestTokenService_GenerateWithResources(t *testing.T) {
	signingKey := []byte("test-signing-key")
	tokenExpiration := 24
	issuer := "test-issuer"
	audience := jwt.ClaimStrings{"test-audience"}
	logger := &MockLogger{}

	// Access the concrete implementation to test GenerateWithResources
	serviceImpl := auth.NewTokenService(signingKey, tokenExpiration, issuer, audience, logger).(*auth.TokenServiceImpl)

	t.Run("generates token with resource roles", func(t *testing.T) {
		identity := &MockIdentity{}
		identity.On("ID").Return("user-123")
		identity.On("Role").Return("member")

		resourceRoles := map[string]string{
			"project-1": "admin",
			"project-2": "owner",
		}

		tokenString, err := serviceImpl.GenerateWithResources(identity, resourceRoles)

		assert.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Parse the token to verify structure
		token, err := jwt.ParseWithClaims(tokenString, &auth.JWTClaims{}, func(token *jwt.Token) (any, error) {
			return signingKey, nil
		})

		assert.NoError(t, err)
		assert.True(t, token.Valid)

		claims, ok := token.Claims.(*auth.JWTClaims)
		assert.True(t, ok)
		assert.Equal(t, "user-123", claims.Subject())
		assert.Equal(t, "member", claims.Role())
		assert.Equal(t, resourceRoles, claims.Resources)

		identity.AssertExpectations(t)
	})

	t.Run("generates token with empty resource roles", func(t *testing.T) {
		identity := &MockIdentity{}
		identity.On("ID").Return("user-123")
		identity.On("Role").Return("guest")

		resourceRoles := map[string]string{}

		tokenString, err := serviceImpl.GenerateWithResources(identity, resourceRoles)

		assert.NoError(t, err)

		token, err := jwt.ParseWithClaims(tokenString, &auth.JWTClaims{}, func(token *jwt.Token) (any, error) {
			return signingKey, nil
		})

		assert.NoError(t, err)
		claims := token.Claims.(*auth.JWTClaims)
		assert.Empty(t, claims.Resources)

		identity.AssertExpectations(t)
	})
}

func TestTokenService_Validate(t *testing.T) {
	signingKey := []byte("test-signing-key")
	tokenExpiration := 24
	issuer := "test-issuer"
	audience := jwt.ClaimStrings{"test-audience"}
	logger := &MockLogger{}

	service := auth.NewTokenService(signingKey, tokenExpiration, issuer, audience, logger)

	t.Run("validates new structured JWT token", func(t *testing.T) {
		// Create a new structured token
		identity := &MockIdentity{}
		identity.On("ID").Return("user-123")
		identity.On("Role").Return("admin")

		tokenString, err := service.Generate(identity)
		assert.NoError(t, err)

		// Validate the token
		claims, err := service.Validate(tokenString)

		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "user-123", claims.Subject())
		assert.Equal(t, "user-123", claims.UserID())
		assert.Equal(t, "admin", claims.Role())

		identity.AssertExpectations(t)
	})

	t.Run("validates legacy MapClaims token", func(t *testing.T) {
		// Create a legacy token with MapClaims format based on existing patterns
		now := time.Now()
		legacyClaims := jwt.MapClaims{
			"iss": issuer,
			"sub": "user-456",
			"aud": audience,
			"iat": jwt.NewNumericDate(now),
			"exp": jwt.NewNumericDate(now.Add(24 * time.Hour)),
			"dat": map[string]any{
				"role": "member",
				"resources": map[string]any{
					"project-1": "owner",
				},
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, legacyClaims)
		tokenString, err := token.SignedString(signingKey)
		assert.NoError(t, err)

		// Validate the legacy token
		claims, err := service.Validate(tokenString)

		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "user-456", claims.Subject())
		assert.Equal(t, "user-456", claims.UserID())
		assert.Equal(t, "member", claims.Role())
		assert.True(t, claims.CanRead("project-1"))
		assert.True(t, claims.CanDelete("project-1")) // owner role can delete
	})

	t.Run("validates legacy MapClaims token without resources", func(t *testing.T) {
		// Create a legacy token without resources
		now := time.Now()
		legacyClaims := jwt.MapClaims{
			"iss": issuer,
			"sub": "user-789",
			"aud": audience,
			"iat": jwt.NewNumericDate(now),
			"exp": jwt.NewNumericDate(now.Add(24 * time.Hour)),
			"dat": map[string]any{
				"role": "guest",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, legacyClaims)
		tokenString, err := token.SignedString(signingKey)
		assert.NoError(t, err)

		// Validate the legacy token
		claims, err := service.Validate(tokenString)

		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "user-789", claims.Subject())
		assert.Equal(t, "guest", claims.Role())
		assert.True(t, claims.CanRead("any-resource"))  // guest can read
		assert.False(t, claims.CanEdit("any-resource")) // guest cannot edit
	})

	t.Run("returns error for expired token", func(t *testing.T) {
		// Create an expired token
		now := time.Now()
		expiredClaims := jwt.MapClaims{
			"iss": issuer,
			"sub": "user-expired",
			"aud": audience,
			"iat": jwt.NewNumericDate(now.Add(-25 * time.Hour)),
			"exp": jwt.NewNumericDate(now.Add(-1 * time.Hour)), // Expired 1 hour ago
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
		tokenString, err := token.SignedString(signingKey)
		assert.NoError(t, err)

		// Try to validate the expired token
		claims, err := service.Validate(tokenString)

		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, auth.ErrTokenExpired)
	})

	t.Run("returns error for malformed token", func(t *testing.T) {
		malformedToken := "not.a.valid.jwt.token"

		claims, err := service.Validate(malformedToken)

		assert.Error(t, err)
		assert.Nil(t, claims)
		// Should be wrapped as ErrTokenMalformed
		assert.Contains(t, err.Error(), "token is malformed")
	})

	t.Run("returns error for token with wrong signing method", func(t *testing.T) {
		// Create a token with RS256 instead of HS256
		wrongClaims := jwt.MapClaims{
			"iss": issuer,
			"sub": "user-123",
			"aud": audience,
			"iat": jwt.NewNumericDate(time.Now()).Unix(),
			"exp": jwt.NewNumericDate(time.Now().Add(24 * time.Hour)).Unix(),
		}

		_ = jwt.NewWithClaims(jwt.SigningMethodRS256, wrongClaims)

		// This will fail because we can't sign with RS256 without proper keys,
		// but let's test with a manually crafted token header
		tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid-signature"

		logger.On("Error", mock.AnythingOfType("string"), mock.Anything, mock.Anything).Maybe()

		claims, err := service.Validate(tokenString)

		assert.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("returns error for token with wrong signing key", func(t *testing.T) {
		// Create a token with a different signing key
		wrongKey := []byte("wrong-signing-key")
		claims := jwt.MapClaims{
			"iss": issuer,
			"sub": "user-123",
			"aud": audience,
			"iat": jwt.NewNumericDate(time.Now()).Unix(),
			"exp": jwt.NewNumericDate(time.Now().Add(24 * time.Hour)).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(wrongKey)
		assert.NoError(t, err)

		// Try to validate with the correct service (which has the correct key)
		validatedClaims, err := service.Validate(tokenString)

		assert.Error(t, err)
		assert.Nil(t, validatedClaims)
	})

	t.Run("handles legacy token with malformed data", func(t *testing.T) {
		// Create a legacy token with malformed dat field
		now := time.Now()
		legacyClaims := jwt.MapClaims{
			"iss": issuer,
			"sub": "user-malformed",
			"aud": audience,
			"iat": jwt.NewNumericDate(now).Unix(),
			"exp": jwt.NewNumericDate(now.Add(24 * time.Hour)).Unix(),
			"dat": "not-an-object", // This should be a map[string]interface{}
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, legacyClaims)
		tokenString, err := token.SignedString(signingKey)
		assert.NoError(t, err)

		// Validate the token with malformed data
		claims, err := service.Validate(tokenString)

		assert.NoError(t, err) // Should not error, just use empty role
		assert.NotNil(t, claims)
		assert.Equal(t, "user-malformed", claims.Subject())
		assert.Equal(t, "", claims.Role()) // Should be empty due to malformed data
	})

	t.Run("handles legacy token with missing claims", func(t *testing.T) {
		// Create a token missing required claims - based on the implementation,
		// the token service is designed to be tolerant of missing claims
		incompleteClaims := jwt.MapClaims{
			"sub": "user-incomplete",
			// Missing iss, aud, iat, exp - the implementation handles these gracefully
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, incompleteClaims)
		tokenString, err := token.SignedString(signingKey)
		assert.NoError(t, err)

		// Validate should succeed but with empty/default values for missing claims
		claims, err := service.Validate(tokenString)

		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "user-incomplete", claims.Subject())
		assert.Equal(t, "", claims.Role()) // Empty role due to missing dat
	})
}

func TestTokenService_Integration(t *testing.T) {
	signingKey := []byte("integration-test-key")
	tokenExpiration := 1 // 1 hour for integration test
	issuer := "integration-issuer"
	audience := jwt.ClaimStrings{"integration-audience"}
	logger := &MockLogger{}

	service := auth.NewTokenService(signingKey, tokenExpiration, issuer, audience, logger)
	serviceImpl := service.(*auth.TokenServiceImpl)

	t.Run("full generate and validate cycle", func(t *testing.T) {
		identity := &MockIdentity{}
		identity.On("ID").Return("integration-user")
		identity.On("Role").Return("admin")

		// Generate token
		tokenString, err := service.Generate(identity)
		assert.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Validate token
		claims, err := service.Validate(tokenString)
		assert.NoError(t, err)
		assert.NotNil(t, claims)

		// Verify claims match original identity
		assert.Equal(t, identity.ID(), claims.Subject())
		assert.Equal(t, identity.ID(), claims.UserID())
		assert.Equal(t, identity.Role(), claims.Role())

		// Test RBAC methods
		assert.True(t, claims.CanRead("any-resource"))
		assert.True(t, claims.CanEdit("any-resource"))
		assert.True(t, claims.CanCreate("any-resource"))
		assert.False(t, claims.CanDelete("any-resource")) // admin can't delete, only owner can
		assert.True(t, claims.HasRole("admin"))
		assert.False(t, claims.HasRole("owner"))
		assert.True(t, claims.IsAtLeast("guest"))
		assert.True(t, claims.IsAtLeast("admin"))
		assert.False(t, claims.IsAtLeast("owner"))

		identity.AssertExpectations(t)
	})

	t.Run("full generate with resources and validate cycle", func(t *testing.T) {
		identity := &MockIdentity{}
		identity.On("ID").Return("resource-user")
		identity.On("Role").Return("member")

		resourceRoles := map[string]string{
			"project-alpha": "admin",
			"project-beta":  "owner",
		}

		// Generate token with resources
		tokenString, err := serviceImpl.GenerateWithResources(identity, resourceRoles)
		assert.NoError(t, err)

		// Validate token
		claims, err := service.Validate(tokenString)
		assert.NoError(t, err)
		assert.NotNil(t, claims)

		// Test global permissions (should use member role)
		assert.True(t, claims.CanRead("unknown-resource"))
		assert.True(t, claims.CanEdit("unknown-resource"))
		assert.False(t, claims.CanCreate("unknown-resource"))
		assert.False(t, claims.CanDelete("unknown-resource"))

		// Test resource-specific permissions
		// project-alpha: admin role
		assert.True(t, claims.CanRead("project-alpha"))
		assert.True(t, claims.CanEdit("project-alpha"))
		assert.True(t, claims.CanCreate("project-alpha"))
		assert.False(t, claims.CanDelete("project-alpha"))

		// project-beta: owner role
		assert.True(t, claims.CanRead("project-beta"))
		assert.True(t, claims.CanEdit("project-beta"))
		assert.True(t, claims.CanCreate("project-beta"))
		assert.True(t, claims.CanDelete("project-beta"))

		// Test role checking
		assert.True(t, claims.HasRole("member")) // global role
		assert.True(t, claims.HasRole("admin"))  // resource role
		assert.True(t, claims.HasRole("owner"))  // resource role
		assert.False(t, claims.HasRole("guest")) // not present anywhere

		identity.AssertExpectations(t)
	})
}
