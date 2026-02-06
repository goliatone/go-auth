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

	t.Run("generates and validates JWT token with structured claims", func(t *testing.T) {
		identity := &MockIdentity{}
		identity.On("ID").Return("user-123")
		identity.On("Role").Return("admin")

		// Generate token
		tokenString, err := service.Generate(identity, map[string]string{})
		assert.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Validate token using TokenService.Validate
		claims, err := service.Validate(tokenString)
		assert.NoError(t, err)
		assert.NotNil(t, claims)

		// Verify AuthClaims interface methods work correctly
		assert.Equal(t, "user-123", claims.Subject())
		assert.Equal(t, "user-123", claims.UserID())
		assert.Equal(t, "admin", claims.Role())

		// Test RBAC methods - admin should have these permissions
		assert.True(t, claims.CanRead("any-resource"))
		assert.True(t, claims.CanEdit("any-resource"))
		assert.True(t, claims.CanCreate("any-resource"))
		assert.False(t, claims.CanDelete("any-resource")) // admin can't delete

		// Test role checking methods
		assert.True(t, claims.HasRole("admin"))
		assert.False(t, claims.HasRole("owner"))
		assert.True(t, claims.IsAtLeast("guest"))
		assert.True(t, claims.IsAtLeast("admin"))
		assert.False(t, claims.IsAtLeast("owner"))

		if tokenIDer, ok := claims.(auth.TokenIDer); assert.True(t, ok) {
			assert.NotEmpty(t, tokenIDer.TokenID())
		}

		identity.AssertExpectations(t)
	})

	t.Run("generates token with correct expiration time", func(t *testing.T) {
		identity := &MockIdentity{}
		identity.On("ID").Return("user-123")
		identity.On("Role").Return("member")

		beforeGenerate := time.Now()
		tokenString, err := service.Generate(identity, map[string]string{})
		afterGenerate := time.Now()

		assert.NoError(t, err)

		// Validate and check expiration through AuthClaims interface
		claims, err := service.Validate(tokenString)
		assert.NoError(t, err)

		expectedExpiry := beforeGenerate.Add(time.Duration(tokenExpiration) * time.Hour)
		actualExpiry := claims.Expires()

		// Verify expiration is set correctly
		assert.False(t, actualExpiry.IsZero())
		assert.True(t, actualExpiry.After(expectedExpiry.Add(-time.Second)))
		assert.True(t, actualExpiry.Before(afterGenerate.Add(time.Duration(tokenExpiration)*time.Hour+time.Second)))

		// Verify issued at time is set
		issuedAt := claims.IssuedAt()
		assert.False(t, issuedAt.IsZero())
		assert.True(t, issuedAt.After(beforeGenerate.Add(-time.Second)))
		assert.True(t, issuedAt.Before(afterGenerate.Add(time.Second)))

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
	service := auth.NewTokenService(signingKey, tokenExpiration, issuer, audience, logger)
	serviceImpl := service.(*auth.TokenServiceImpl)

	t.Run("generates and validates token with resource roles", func(t *testing.T) {
		identity := &MockIdentity{}
		identity.On("ID").Return("user-123")
		identity.On("Role").Return("member")

		resourceRoles := map[string]string{
			"project-1": "admin",
			"project-2": "owner",
		}

		// Generate token with resources
		tokenString, err := serviceImpl.Generate(identity, resourceRoles)
		assert.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Validate token using TokenService.Validate
		claims, err := service.Validate(tokenString)
		assert.NoError(t, err)
		assert.NotNil(t, claims)

		// Verify basic claims
		assert.Equal(t, "user-123", claims.Subject())
		assert.Equal(t, "member", claims.Role())

		// Test global permissions (should use member role)
		assert.True(t, claims.CanRead("unknown-resource"))
		assert.True(t, claims.CanEdit("unknown-resource"))
		assert.False(t, claims.CanCreate("unknown-resource"))
		assert.False(t, claims.CanDelete("unknown-resource"))

		// Test resource-specific permissions
		// project-1: admin role
		assert.True(t, claims.CanRead("project-1"))
		assert.True(t, claims.CanEdit("project-1"))
		assert.True(t, claims.CanCreate("project-1"))
		assert.False(t, claims.CanDelete("project-1"))

		// project-2: owner role
		assert.True(t, claims.CanRead("project-2"))
		assert.True(t, claims.CanEdit("project-2"))
		assert.True(t, claims.CanCreate("project-2"))
		assert.True(t, claims.CanDelete("project-2"))

		// Test role checking (should have member globally, admin and owner for resources)
		assert.True(t, claims.HasRole("member"))
		assert.True(t, claims.HasRole("admin"))  // resource role
		assert.True(t, claims.HasRole("owner"))  // resource role
		assert.False(t, claims.HasRole("guest")) // not present anywhere

		identity.AssertExpectations(t)
	})

	t.Run("generates and validates token with empty resource roles", func(t *testing.T) {
		identity := &MockIdentity{}
		identity.On("ID").Return("user-123")
		identity.On("Role").Return("guest")

		resourceRoles := map[string]string{}

		// Generate token with empty resources
		tokenString, err := serviceImpl.Generate(identity, resourceRoles)
		assert.NoError(t, err)

		// Validate and verify the token works like a normal token
		claims, err := service.Validate(tokenString)
		assert.NoError(t, err)

		// Should behave like guest role globally
		assert.True(t, claims.CanRead("any-resource"))
		assert.False(t, claims.CanEdit("any-resource"))
		assert.False(t, claims.CanCreate("any-resource"))
		assert.False(t, claims.CanDelete("any-resource"))

		assert.True(t, claims.HasRole("guest"))
		assert.False(t, claims.HasRole("member"))

		identity.AssertExpectations(t)
	})
}

func TestTokenService_SignClaims(t *testing.T) {
	signingKey := []byte("test-signing-key")
	tokenExpiration := 24
	issuer := "test-issuer"
	audience := jwt.ClaimStrings{"test-audience"}
	logger := &MockLogger{}

	service := auth.NewTokenService(signingKey, tokenExpiration, issuer, audience, logger)
	impl := service.(*auth.TokenServiceImpl)

	t.Run("signs decorated claims", func(t *testing.T) {
		now := time.Now()
		claims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "user-123",
				Audience:  audience,
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(tokenExpiration) * time.Hour)),
			},
			UID:      "user-123",
			UserRole: "admin",
			Metadata: map[string]any{"tenant": "acme"},
		}

		token, err := impl.SignClaims(claims)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		parsed, err := service.Validate(token)
		assert.NoError(t, err)

		jwtClaims, ok := parsed.(*auth.JWTClaims)
		assert.True(t, ok)
		assert.Equal(t, "acme", jwtClaims.Metadata["tenant"])
	})

	t.Run("returns error when claims nil", func(t *testing.T) {
		token, err := impl.SignClaims(nil)
		assert.Error(t, err)
		assert.Empty(t, token)
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

		tokenString, err := service.Generate(identity, map[string]string{})
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

	t.Run("returns error for expired token", func(t *testing.T) {
		// Create an expired token using JWTClaims
		now := time.Now()
		expiredClaims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "user-expired",
				Audience:  audience,
				IssuedAt:  jwt.NewNumericDate(now.Add(-25 * time.Hour)),
				ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)), // Expired 1 hour ago
			},
			UID:       "user-expired",
			UserRole:  "member",
			Resources: make(map[string]string),
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
		// Create a token with a different signing key using JWTClaims
		wrongKey := []byte("wrong-signing-key")
		now := time.Now()
		claims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "user-123",
				Audience:  audience,
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			},
			UID:       "user-123",
			UserRole:  "member",
			Resources: make(map[string]string),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(wrongKey)
		assert.NoError(t, err)

		// Try to validate with the correct service (which has the correct key)
		validatedClaims, err := service.Validate(tokenString)

		assert.Error(t, err)
		assert.Nil(t, validatedClaims)
	})

}

func TestMintScopedToken(t *testing.T) {
	signingKey := []byte("test-signing-key")
	tokenExpiration := 24
	issuer := "test-issuer"
	audience := jwt.ClaimStrings{"test-audience"}
	logger := &MockLogger{}

	service := auth.NewTokenService(signingKey, tokenExpiration, issuer, audience, logger)

	t.Run("mints token with TTL override and scopes", func(t *testing.T) {
		identity := &MockIdentity{}
		identity.On("ID").Return("user-123")
		identity.On("Role").Return("admin")

		issuedAt := time.Now().UTC().Truncate(jwt.TimePrecision)
		opts := auth.ScopedTokenOptions{
			TTL:      30 * time.Minute,
			Scopes:   []string{"debug.view", "debug.repl"},
			IssuedAt: issuedAt,
		}

		token, expiresAt, err := auth.MintScopedToken(service, identity, map[string]string{}, opts)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.Equal(t, issuedAt.Add(30*time.Minute), expiresAt)

		claims, err := service.Validate(token)
		if !assert.NoError(t, err) {
			return
		}

		jwtClaims, ok := claims.(*auth.JWTClaims)
		assert.True(t, ok)
		assert.Equal(t, opts.Scopes, jwtClaims.Scopes)
		assert.NotEmpty(t, jwtClaims.RegisteredClaims.ID)
		assert.Equal(t, issuer, jwtClaims.RegisteredClaims.Issuer)
		assert.Equal(t, audience, jwtClaims.RegisteredClaims.Audience)
		assert.True(t, expiresAt.Equal(jwtClaims.RegisteredClaims.ExpiresAt.Time))

		identity.AssertExpectations(t)
	})

	t.Run("uses token service defaults when TTL is zero", func(t *testing.T) {
		identity := &MockIdentity{}
		identity.On("ID").Return("user-456")
		identity.On("Role").Return("member")

		issuedAt := time.Now().UTC().Truncate(jwt.TimePrecision)
		opts := auth.ScopedTokenOptions{
			IssuedAt: issuedAt,
		}

		token, expiresAt, err := auth.MintScopedToken(service, identity, map[string]string{}, opts)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.Equal(t, issuedAt.Add(24*time.Hour), expiresAt)

		claims, err := service.Validate(token)
		if !assert.NoError(t, err) {
			return
		}

		jwtClaims, ok := claims.(*auth.JWTClaims)
		assert.True(t, ok)
		assert.True(t, expiresAt.Equal(jwtClaims.RegisteredClaims.ExpiresAt.Time))

		identity.AssertExpectations(t)
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
		tokenString, err := service.Generate(identity, map[string]string{})
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
		tokenString, err := serviceImpl.Generate(identity, resourceRoles)
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
