package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-auth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestIdentity is a simple implementation of Identity interface for testing
type TestIdentity struct {
	id       string
	username string
	email    string
	role     string
	status   auth.UserStatus
}

func (t TestIdentity) ID() string       { return t.id }
func (t TestIdentity) Username() string { return t.username }
func (t TestIdentity) Email() string    { return t.email }
func (t TestIdentity) Role() string     { return t.role }
func (t TestIdentity) Status() auth.UserStatus {
	if t.status == "" {
		return auth.UserStatusActive
	}
	return t.status
}

func newMockConfig() *MockConfig {
	mockConfig := new(MockConfig)
	mockConfig.On("GetSigningKey").Return("test-signing-key")
	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetIssuer").Return("test-issuer")
	mockConfig.On("GetAudience").Return([]string{"test:audience"})
	return mockConfig
}

func TestLogin(t *testing.T) {
	// Setup test environment
	ctx := context.Background()
	mockProvider := new(MockIdentityProvider)
	mockConfig := new(MockConfig)

	// Configure mock config
	mockConfig.On("GetSigningKey").Return("test-signing-key")
	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetIssuer").Return("test-issuer")
	mockConfig.On("GetAudience").Return([]string{"test:audience"})

	// Create authenticator
	authenticator := auth.NewAuthenticator(mockProvider, mockConfig)

	// Test cases
	t.Run("Successful login", func(t *testing.T) {
		identity := TestIdentity{
			id:       uuid.New().String(),
			username: "testuser",
			email:    "test@example.com",
			role:     "admin",
			status:   auth.UserStatusActive,
		}

		mockProvider.On("VerifyIdentity", ctx, "test@example.com", "password123").
			Return(identity, nil).Once()

		token, err := authenticator.Login(ctx, "test@example.com", "password123")

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token can be parsed and contains correct claims using new structure
		parsedToken, err := jwt.ParseWithClaims(token, &auth.JWTClaims{}, func(t *jwt.Token) (any, error) {
			return []byte("test-signing-key"), nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		claims, ok := parsedToken.Claims.(*auth.JWTClaims)
		assert.True(t, ok)
		assert.Equal(t, identity.ID(), claims.Subject())
		assert.Equal(t, "test-issuer", claims.RegisteredClaims.Issuer)
		assert.Equal(t, jwt.ClaimStrings{"test:audience"}, claims.RegisteredClaims.Audience)
		assert.NotEmpty(t, claims.RegisteredClaims.ID)

		// Verify role is directly in the claims
		assert.Equal(t, "admin", claims.UserRole)
	})

	t.Run("Failed login - invalid credentials", func(t *testing.T) {
		mockProvider.On("VerifyIdentity", ctx, "bad@example.com", "wrongpassword").
			Return(nil, errors.New("invalid credentials")).Once()

		token, err := authenticator.Login(ctx, "bad@example.com", "wrongpassword")

		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "invalid credentials")
	})

	t.Run("Failed login - identity not found", func(t *testing.T) {
		mockProvider.On("VerifyIdentity", ctx, "unknown@example.com", "password123").
			Return(nil, auth.ErrIdentityNotFound).Once()

		token, err := authenticator.Login(ctx, "unknown@example.com", "password123")

		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "identity not found")
	})

	t.Run("Login blocked when status inactive", func(t *testing.T) {
		identity := TestIdentity{
			id:       uuid.New().String(),
			username: "frozen",
			email:    "suspended@example.com",
			role:     "member",
			status:   auth.UserStatusSuspended,
		}

		mockProvider.On("VerifyIdentity", ctx, identity.email, "password123").
			Return(identity, nil).Once()

		token, err := authenticator.Login(ctx, identity.email, "password123")

		assert.ErrorIs(t, err, auth.ErrUserSuspended)
		assert.Empty(t, token)
	})
}

func TestImpersonate(t *testing.T) {
	// Setup test environment
	ctx := context.Background()
	mockProvider := new(MockIdentityProvider)
	mockConfig := new(MockConfig)

	// Configure mock config
	mockConfig.On("GetSigningKey").Return("test-signing-key")
	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetIssuer").Return("test-issuer")
	mockConfig.On("GetAudience").Return([]string{"test:audience"})

	// Create authenticator
	authenticator := auth.NewAuthenticator(mockProvider, mockConfig)

	// Test cases
	t.Run("Successful impersonation", func(t *testing.T) {
		identity := TestIdentity{
			id:       uuid.New().String(),
			username: "adminuser",
			email:    "admin@example.com",
			role:     "admin",
			status:   auth.UserStatusActive,
		}

		mockProvider.On("FindIdentityByIdentifier", ctx, "admin@example.com").
			Return(identity, nil).Once()

		token, err := authenticator.Impersonate(ctx, "admin@example.com")

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token can be parsed and contains correct claims using new structure
		parsedToken, err := jwt.ParseWithClaims(token, &auth.JWTClaims{}, func(t *jwt.Token) (any, error) {
			return []byte("test-signing-key"), nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		claims, ok := parsedToken.Claims.(*auth.JWTClaims)
		assert.True(t, ok)
		assert.Equal(t, identity.ID(), claims.Subject())
		assert.Equal(t, "test-issuer", claims.RegisteredClaims.Issuer)
		assert.Equal(t, jwt.ClaimStrings{"test:audience"}, claims.RegisteredClaims.Audience)

		// Verify role is directly in the claims
		assert.Equal(t, "admin", claims.UserRole)
	})

	t.Run("Failed impersonation - identity not found", func(t *testing.T) {
		mockProvider.On("FindIdentityByIdentifier", ctx, "unknown@example.com").
			Return(nil, auth.ErrIdentityNotFound).Once()

		token, err := authenticator.Impersonate(ctx, "unknown@example.com")

		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "identity not found")
	})

	t.Run("Impersonation blocked when status inactive", func(t *testing.T) {
		identity := TestIdentity{
			id:       uuid.New().String(),
			username: "blocked-admin",
			email:    "blocked@example.com",
			role:     "admin",
			status:   auth.UserStatusDisabled,
		}

		mockProvider.On("FindIdentityByIdentifier", ctx, identity.email).
			Return(identity, nil).Once()

		token, err := authenticator.Impersonate(ctx, identity.email)

		assert.ErrorIs(t, err, auth.ErrUserDisabled)
		assert.Empty(t, token)
	})
}

func TestSessionFromToken(t *testing.T) {
	mockProvider := new(MockIdentityProvider)
	mockConfig := new(MockConfig)

	mockConfig.On("GetSigningKey").Return("test-signing-key")
	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetIssuer").Return("test-issuer")
	mockConfig.On("GetAudience").Return([]string{"test:audience"})

	authenticator := auth.NewAuthenticator(mockProvider, mockConfig)

	// create a valid token for testing using new JWTClaims structure
	now := time.Now()
	userID := uuid.New().String()
	expiry := now.Add(24 * time.Hour)

	claims := &auth.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Audience:  []string{"test:audience"},
			Issuer:    "test-issuer",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiry),
		},
		UID:       userID,
		UserRole:  "admin",
		Resources: make(map[string]string),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("test-signing-key"))
	assert.NoError(t, err)

	t.Run("Valid token", func(t *testing.T) {
		session, err := authenticator.SessionFromToken(tokenString)

		assert.NoError(t, err)
		assert.NotNil(t, session)

		assert.Equal(t, userID, session.GetUserID())
		assert.Equal(t, []string{"test:audience"}, session.GetAudience())
		assert.Equal(t, "test-issuer", session.GetIssuer())

		data := session.GetData()
		assert.Equal(t, "admin", data["role"])
	})

	t.Run("Invalid token signature", func(t *testing.T) {
		badToken := tokenString + "tampered"
		session, err := authenticator.SessionFromToken(badToken)

		assert.Error(t, err)
		assert.Nil(t, session)
	})

	t.Run("Expired token", func(t *testing.T) {
		// create an expired token using new JWTClaims structure
		expiredClaims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   userID,
				Audience:  []string{"test:audience"},
				Issuer:    "test-issuer",
				IssuedAt:  jwt.NewNumericDate(now.Add(-48 * time.Hour)),
				ExpiresAt: jwt.NewNumericDate(now.Add(-24 * time.Hour)), // Expired 24 hours ago
			},
			UID:       userID,
			UserRole:  "admin",
			Resources: make(map[string]string),
		}

		expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
		expiredTokenString, _ := expiredToken.SignedString([]byte("test-signing-key"))

		session, err := authenticator.SessionFromToken(expiredTokenString)

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("Legacy token format rejected", func(t *testing.T) {
		// Create a legacy token with MapClaims format that has incompatible structure
		legacyClaims := jwt.MapClaims{
			"sub": userID,
			"aud": []string{"test:audience"},
			"iss": "test-issuer",
			"iat": jwt.NewNumericDate(now),
			"exp": jwt.NewNumericDate(expiry),
			// Legacy tokens store data in "dat" field, not directly in claims
			"dat": map[string]any{
				"role": "admin",
			},
		}

		legacyToken := jwt.NewWithClaims(jwt.SigningMethodHS256, legacyClaims)
		legacyTokenString, _ := legacyToken.SignedString([]byte("test-signing-key"))

		session, err := authenticator.SessionFromToken(legacyTokenString)

		// Legacy tokens should be rejected or return sessions with empty role data
		// because they don't match the expected JWTClaims structure
		if err == nil {
			// If parsing succeeds, the session should have empty/missing role data
			// because legacy format stores role in "dat" field, not in root claims
			assert.NotNil(t, session)
			data := session.GetData()
			// Role should be empty because legacy "dat" field is not parsed
			assert.Equal(t, "", data["role"])
		} else {
			// Token validation failed, which is expected for legacy tokens
			assert.Nil(t, session)
			assert.Error(t, err)
		}
	})
}

func TestLoginActivitySink(t *testing.T) {
	ctx := context.Background()
	identity := TestIdentity{
		id:       uuid.New().String(),
		username: "audit-user",
		email:    "audit@example.com",
		role:     "member",
		status:   auth.UserStatusActive,
	}

	t.Run("success event", func(t *testing.T) {
		provider := new(MockIdentityProvider)
		config := newMockConfig()
		sink := new(MockActivitySink)

		authenticator := auth.NewAuthenticator(provider, config).WithActivitySink(sink)

		provider.On("VerifyIdentity", ctx, identity.Email(), "password").
			Return(identity, nil).Once()

		sink.On("Record", mock.Anything, mock.MatchedBy(func(evt auth.ActivityEvent) bool {
			return evt.EventType == auth.ActivityEventLoginSuccess &&
				evt.UserID == identity.ID()
		})).Return(nil).Once()

		_, err := authenticator.Login(ctx, identity.Email(), "password")
		require.NoError(t, err)

		sink.AssertExpectations(t)
		provider.AssertExpectations(t)
	})

	t.Run("failure event", func(t *testing.T) {
		provider := new(MockIdentityProvider)
		config := newMockConfig()
		sink := new(MockActivitySink)

		authenticator := auth.NewAuthenticator(provider, config).WithActivitySink(sink)

		provider.On("VerifyIdentity", ctx, "unknown@example.com", "password").
			Return(nil, errors.New("boom")).Once()

		sink.On("Record", mock.Anything, mock.MatchedBy(func(evt auth.ActivityEvent) bool {
			return evt.EventType == auth.ActivityEventLoginFailure &&
				evt.UserID == "" &&
				evt.Metadata["identifier"] == "unknown@example.com"
		})).Return(nil).Once()

		_, err := authenticator.Login(ctx, "unknown@example.com", "password")
		require.Error(t, err)

		sink.AssertExpectations(t)
		provider.AssertExpectations(t)
	})
}

func TestIdentityFromSession(t *testing.T) {
	ctx := context.Background()
	mockProvider := new(MockIdentityProvider)
	mockConfig := new(MockConfig)

	mockConfig.On("GetSigningKey").Return("test-signing-key")
	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetIssuer").Return("test-issuer")
	mockConfig.On("GetAudience").Return([]string{"test:audience"})

	authenticator := auth.NewAuthenticator(mockProvider, mockConfig)

	// create a mock session
	userID := uuid.New().String()
	now := time.Now()
	session := &auth.SessionObject{
		UserID:   userID,
		Audience: []string{"test:audience"},
		Issuer:   "test-issuer",
		IssuedAt: &now,
		Data:     map[string]any{"role": "admin"},
	}

	t.Run("Identity found", func(t *testing.T) {
		identity := TestIdentity{
			id:       userID,
			username: "testuser",
			email:    "test@example.com",
			role:     "admin",
			status:   auth.UserStatusActive,
		}

		mockProvider.On("FindIdentityByIdentifier", ctx, userID).
			Return(identity, nil).Once()

		result, err := authenticator.IdentityFromSession(ctx, session)

		assert.NoError(t, err)
		assert.Equal(t, identity.ID(), result.ID())
		assert.Equal(t, identity.Username(), result.Username())
		assert.Equal(t, identity.Email(), result.Email())
		assert.Equal(t, identity.Role(), result.Role())
	})

	t.Run("Identity not found", func(t *testing.T) {
		mockProvider.On("FindIdentityByIdentifier", ctx, userID).
			Return(nil, auth.ErrIdentityNotFound).Once()

		result, err := authenticator.IdentityFromSession(ctx, session)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "identity not found")
	})
}

func TestNewAuthenticator(t *testing.T) {
	t.Run("Initializes with no-op resource role provider", func(t *testing.T) {
		mockProvider := new(MockIdentityProvider)
		mockConfig := new(MockConfig)

		// Configure mock config
		mockConfig.On("GetSigningKey").Return("test-signing-key")
		mockConfig.On("GetTokenExpiration").Return(24)
		mockConfig.On("GetIssuer").Return("test-issuer")
		mockConfig.On("GetAudience").Return([]string{"test:audience"})

		authenticator := auth.NewAuthenticator(mockProvider, mockConfig)

		// Verify that the authenticator was created successfully
		assert.NotNil(t, authenticator)

		// Test that login works with the default no-op provider (should produce empty resource roles)
		ctx := context.Background()
		identity := TestIdentity{
			id:       uuid.New().String(),
			username: "testuser",
			email:    "test@example.com",
			role:     "admin",
			status:   auth.UserStatusActive,
		}

		mockProvider.On("VerifyIdentity", ctx, "test@example.com", "password123").
			Return(identity, nil).Once()

		token, err := authenticator.Login(ctx, "test@example.com", "password123")
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token uses empty resource roles (from no-op provider)
		parsedToken, err := jwt.ParseWithClaims(token, &auth.JWTClaims{}, func(t *jwt.Token) (any, error) {
			return []byte("test-signing-key"), nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		claims, ok := parsedToken.Claims.(*auth.JWTClaims)
		assert.True(t, ok)
		assert.Equal(t, identity.ID(), claims.Subject())
		assert.Equal(t, "admin", claims.UserRole)
		// Resources should be empty/nil from no-op provider (omitempty in JSON)
		if claims.Resources != nil {
			assert.Empty(t, claims.Resources)
		}
	})
}

func TestWithResourceRoleProvider(t *testing.T) {
	t.Run("Sets custom resource role provider", func(t *testing.T) {
		mockProvider := new(MockIdentityProvider)
		mockConfig := new(MockConfig)
		mockRoleProvider := new(MockResourceRoleProvider)

		// Configure mock config
		mockConfig.On("GetSigningKey").Return("test-signing-key")
		mockConfig.On("GetTokenExpiration").Return(24)
		mockConfig.On("GetIssuer").Return("test-issuer")
		mockConfig.On("GetAudience").Return([]string{"test:audience"})

		authenticator := auth.NewAuthenticator(mockProvider, mockConfig).
			WithResourceRoleProvider(mockRoleProvider)

		// Verify that the authenticator was created successfully
		assert.NotNil(t, authenticator)

		// Test that login now uses the custom provider
		ctx := context.Background()
		identity := TestIdentity{
			id:       uuid.New().String(),
			username: "testuser",
			email:    "test@example.com",
			role:     "admin",
			status:   auth.UserStatusActive,
		}

		resourceRoles := map[string]string{
			"project:123": "owner",
			"project:456": "member",
		}

		mockProvider.On("VerifyIdentity", ctx, "test@example.com", "password123").
			Return(identity, nil).Once()
		mockRoleProvider.On("FindResourceRoles", ctx, identity).
			Return(resourceRoles, nil).Once()

		token, err := authenticator.Login(ctx, "test@example.com", "password123")
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token uses the custom provider's resource roles
		parsedToken, err := jwt.ParseWithClaims(token, &auth.JWTClaims{}, func(t *jwt.Token) (any, error) {
			return []byte("test-signing-key"), nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		claims, ok := parsedToken.Claims.(*auth.JWTClaims)
		assert.True(t, ok)
		assert.Equal(t, identity.ID(), claims.Subject())
		assert.Equal(t, "admin", claims.UserRole)
		assert.Equal(t, resourceRoles, claims.Resources)

		// Verify mock was called
		mockRoleProvider.AssertExpectations(t)
	})
}

func TestClaimsDecoratorIntegration(t *testing.T) {
	ctx := context.Background()
	mockProvider := new(MockIdentityProvider)
	mockConfig := newMockConfig()

	identity := TestIdentity{
		id:       uuid.New().String(),
		username: "decorator-user",
		email:    "decorator@example.com",
		role:     "admin",
		status:   auth.UserStatusActive,
	}

	mockProvider.On("VerifyIdentity", ctx, identity.email, "password123").
		Return(identity, nil).Once()

	decorator := auth.ClaimsDecoratorFunc(func(ctx context.Context, identity auth.Identity, claims *auth.JWTClaims) error {
		if claims.Metadata == nil {
			claims.Metadata = map[string]any{}
		}
		claims.Metadata["tenant"] = "acme"
		if claims.Resources == nil {
			claims.Resources = map[string]string{}
		}
		claims.Resources["project:alpha"] = "editor"
		return nil
	})

	authenticator := auth.NewAuthenticator(mockProvider, mockConfig).
		WithClaimsDecorator(decorator)

	token, err := authenticator.Login(ctx, identity.email, "password123")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	parsedClaims, err := authenticator.TokenService().Validate(token)
	require.NoError(t, err)

	jwtClaims, ok := parsedClaims.(*auth.JWTClaims)
	require.True(t, ok)
	assert.Equal(t, "acme", jwtClaims.Metadata["tenant"])
	assert.Equal(t, "editor", jwtClaims.Resources["project:alpha"])

	session, err := authenticator.SessionFromToken(token)
	require.NoError(t, err)
	metadata, ok := session.GetData()["metadata"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "acme", metadata["tenant"])

	mockProvider.AssertExpectations(t)
}

func TestClaimsDecoratorErrorStopsLogin(t *testing.T) {
	ctx := context.Background()
	mockProvider := new(MockIdentityProvider)
	mockConfig := newMockConfig()

	identity := TestIdentity{
		id:       uuid.New().String(),
		username: "decorator-user",
		email:    "decorator-error@example.com",
		role:     "admin",
		status:   auth.UserStatusActive,
	}

	mockProvider.On("VerifyIdentity", ctx, identity.email, "password123").
		Return(identity, nil).Once()

	expectedErr := errors.New("decorator boom")
	decorator := auth.ClaimsDecoratorFunc(func(ctx context.Context, identity auth.Identity, claims *auth.JWTClaims) error {
		return expectedErr
	})

	authenticator := auth.NewAuthenticator(mockProvider, mockConfig).
		WithClaimsDecorator(decorator)

	token, err := authenticator.Login(ctx, identity.email, "password123")
	assert.ErrorIs(t, err, expectedErr)
	assert.Empty(t, token)

	mockProvider.AssertExpectations(t)
}

func TestClaimsDecoratorImmutableGuard(t *testing.T) {
	ctx := context.Background()
	mockProvider := new(MockIdentityProvider)
	mockConfig := newMockConfig()

	identity := TestIdentity{
		id:       uuid.New().String(),
		username: "immutable-user",
		email:    "immutable@example.com",
		role:     "admin",
		status:   auth.UserStatusActive,
	}

	mockProvider.On("VerifyIdentity", ctx, identity.email, "password123").
		Return(identity, nil).Once()

	decorator := auth.ClaimsDecoratorFunc(func(ctx context.Context, identity auth.Identity, claims *auth.JWTClaims) error {
		claims.RegisteredClaims.Subject = "mutated"
		return nil
	})

	authenticator := auth.NewAuthenticator(mockProvider, mockConfig).
		WithClaimsDecorator(decorator)

	token, err := authenticator.Login(ctx, identity.email, "password123")
	assert.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrImmutableClaimMutation)
	assert.Empty(t, token)

	mockProvider.AssertExpectations(t)
}

func TestLoginWithResourceRoleProvider(t *testing.T) {
	ctx := context.Background()
	mockProvider := new(MockIdentityProvider)
	mockConfig := new(MockConfig)
	mockRoleProvider := new(MockResourceRoleProvider)

	// Configure mock config
	mockConfig.On("GetSigningKey").Return("test-signing-key")
	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetIssuer").Return("test-issuer")
	mockConfig.On("GetAudience").Return([]string{"test:audience"})

	identity := TestIdentity{
		id:       uuid.New().String(),
		username: "testuser",
		email:    "test@example.com",
		role:     "admin",
		status:   auth.UserStatusActive,
	}

	t.Run("Default path - no-op role provider", func(t *testing.T) {
		// Create authenticator with default no-op provider
		authenticator := auth.NewAuthenticator(mockProvider, mockConfig)

		mockProvider.On("VerifyIdentity", ctx, "test@example.com", "password123").
			Return(identity, nil).Once()

		token, err := authenticator.Login(ctx, "test@example.com", "password123")

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token uses empty resources from no-op provider
		parsedToken, err := jwt.ParseWithClaims(token, &auth.JWTClaims{}, func(t *jwt.Token) (any, error) {
			return []byte("test-signing-key"), nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		claims, ok := parsedToken.Claims.(*auth.JWTClaims)
		assert.True(t, ok)
		assert.Equal(t, identity.ID(), claims.Subject())
		assert.Equal(t, "admin", claims.UserRole)
		// Resources should be empty/nil from no-op provider (omitempty in JSON)
		if claims.Resources != nil {
			assert.Empty(t, claims.Resources)
		}
	})

	t.Run("Enhanced path - with custom role provider", func(t *testing.T) {
		// Create authenticator and add custom role provider
		authenticator := auth.NewAuthenticator(mockProvider, mockConfig).
			WithResourceRoleProvider(mockRoleProvider)

		resourceRoles := map[string]string{
			"project:123": "owner",
			"project:456": "member",
		}

		mockProvider.On("VerifyIdentity", ctx, "test@example.com", "password123").
			Return(identity, nil).Once()
		mockRoleProvider.On("FindResourceRoles", ctx, identity).
			Return(resourceRoles, nil).Once()

		token, err := authenticator.Login(ctx, "test@example.com", "password123")

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token uses the custom provider's resource roles
		parsedToken, err := jwt.ParseWithClaims(token, &auth.JWTClaims{}, func(t *jwt.Token) (any, error) {
			return []byte("test-signing-key"), nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		claims, ok := parsedToken.Claims.(*auth.JWTClaims)
		assert.True(t, ok)
		assert.Equal(t, identity.ID(), claims.Subject())
		assert.Equal(t, "admin", claims.UserRole)
		assert.Equal(t, resourceRoles, claims.Resources) // Resources should be present

		// Verify mock was called
		mockRoleProvider.AssertExpectations(t)
	})

	t.Run("Enhanced path - role provider error", func(t *testing.T) {
		// Create authenticator and add role provider
		authenticator := auth.NewAuthenticator(mockProvider, mockConfig).
			WithResourceRoleProvider(mockRoleProvider)

		mockProvider.On("VerifyIdentity", ctx, "test@example.com", "password123").
			Return(identity, nil).Once()
		mockRoleProvider.On("FindResourceRoles", ctx, identity).
			Return(nil, errors.New("permission lookup failed")).Once()

		token, err := authenticator.Login(ctx, "test@example.com", "password123")

		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "permission lookup failed")

		// Verify mock was called
		mockRoleProvider.AssertExpectations(t)
	})
}

func TestImpersonateWithResourceRoleProvider(t *testing.T) {
	ctx := context.Background()
	mockProvider := new(MockIdentityProvider)
	mockConfig := new(MockConfig)
	mockRoleProvider := new(MockResourceRoleProvider)

	// Configure mock config
	mockConfig.On("GetSigningKey").Return("test-signing-key")
	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetIssuer").Return("test-issuer")
	mockConfig.On("GetAudience").Return([]string{"test:audience"})

	identity := TestIdentity{
		id:       uuid.New().String(),
		username: "adminuser",
		email:    "admin@example.com",
		role:     "admin",
		status:   auth.UserStatusActive,
	}

	t.Run("Default path - no-op role provider", func(t *testing.T) {
		// Create authenticator with default no-op provider
		authenticator := auth.NewAuthenticator(mockProvider, mockConfig)

		mockProvider.On("FindIdentityByIdentifier", ctx, "admin@example.com").
			Return(identity, nil).Once()

		token, err := authenticator.Impersonate(ctx, "admin@example.com")

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token uses empty resources from no-op provider
		parsedToken, err := jwt.ParseWithClaims(token, &auth.JWTClaims{}, func(t *jwt.Token) (any, error) {
			return []byte("test-signing-key"), nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		claims, ok := parsedToken.Claims.(*auth.JWTClaims)
		assert.True(t, ok)
		assert.Equal(t, identity.ID(), claims.Subject())
		assert.Equal(t, "admin", claims.UserRole)
		// Resources should be empty/nil from no-op provider (omitempty in JSON)
		if claims.Resources != nil {
			assert.Empty(t, claims.Resources)
		}
	})

	t.Run("Enhanced path - with custom role provider", func(t *testing.T) {
		// Create authenticator and add custom role provider
		authenticator := auth.NewAuthenticator(mockProvider, mockConfig).
			WithResourceRoleProvider(mockRoleProvider)

		resourceRoles := map[string]string{
			"admin:panel":   "owner",
			"system:config": "admin",
		}

		mockProvider.On("FindIdentityByIdentifier", ctx, "admin@example.com").
			Return(identity, nil).Once()
		mockRoleProvider.On("FindResourceRoles", ctx, identity).
			Return(resourceRoles, nil).Once()

		token, err := authenticator.Impersonate(ctx, "admin@example.com")

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token uses the custom provider's resource roles
		parsedToken, err := jwt.ParseWithClaims(token, &auth.JWTClaims{}, func(t *jwt.Token) (any, error) {
			return []byte("test-signing-key"), nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		claims, ok := parsedToken.Claims.(*auth.JWTClaims)
		assert.True(t, ok)
		assert.Equal(t, identity.ID(), claims.Subject())
		assert.Equal(t, "admin", claims.UserRole)
		assert.Equal(t, resourceRoles, claims.Resources) // Resources should be present

		// Verify mock was called
		mockRoleProvider.AssertExpectations(t)
	})

	t.Run("Enhanced path - role provider error", func(t *testing.T) {
		// Create authenticator and add role provider
		authenticator := auth.NewAuthenticator(mockProvider, mockConfig).
			WithResourceRoleProvider(mockRoleProvider)

		mockProvider.On("FindIdentityByIdentifier", ctx, "admin@example.com").
			Return(identity, nil).Once()
		mockRoleProvider.On("FindResourceRoles", ctx, identity).
			Return(nil, errors.New("resource access denied")).Once()

		token, err := authenticator.Impersonate(ctx, "admin@example.com")

		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "resource access denied")

		// Verify mock was called
		mockRoleProvider.AssertExpectations(t)
	})
}
