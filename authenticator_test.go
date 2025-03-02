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
)

// MockIdentityProvider is a mock of the IdentityProvider interface
type MockIdentityProvider struct {
	mock.Mock
}

func (m *MockIdentityProvider) VerifyIdentity(ctx context.Context, identifier, password string) (auth.Identity, error) {
	args := m.Called(ctx, identifier, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(auth.Identity), args.Error(1)
}

func (m *MockIdentityProvider) FindIdentityByIdentifier(ctx context.Context, identifier string) (auth.Identity, error) {
	args := m.Called(ctx, identifier)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(auth.Identity), args.Error(1)
}

// MockConfig for testing authenticator
type MockConfig struct {
	mock.Mock
}

func (m *MockConfig) GetSigningKey() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetSigningMethod() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetContextKey() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetTokenExpiration() int {
	args := m.Called()
	return args.Int(0)
}

func (m *MockConfig) GetExtendedTokenDuration() int {
	args := m.Called()
	return args.Int(0)
}

func (m *MockConfig) GetTokenLookup() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetAuthScheme() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetIssuer() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetAudience() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockConfig) GetRejectedRouteKey() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetRejectedRouteDefault() string {
	args := m.Called()
	return args.String(0)
}

// TestIdentity is a simple implementation of Identity interface for testing
type TestIdentity struct {
	id       string
	username string
	email    string
	role     string
}

func (t TestIdentity) ID() string       { return t.id }
func (t TestIdentity) Username() string { return t.username }
func (t TestIdentity) Email() string    { return t.email }
func (t TestIdentity) Role() string     { return t.role }

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
		}

		mockProvider.On("VerifyIdentity", ctx, "test@example.com", "password123").
			Return(identity, nil).Once()

		token, err := authenticator.Login(ctx, "test@example.com", "password123")

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token can be parsed and contains correct claims
		parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
			return []byte("test-signing-key"), nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		assert.True(t, ok)
		assert.Equal(t, identity.ID(), claims["sub"])
		assert.Equal(t, "test-issuer", claims["iss"])
		assert.Equal(t, []any{"test:audience"}, claims["aud"])

		// Verify role is in the data claims
		datClaims, ok := claims["dat"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "admin", datClaims["role"])
	})

	t.Run("Failed login - invalid credentials", func(t *testing.T) {
		mockProvider.On("VerifyIdentity", ctx, "bad@example.com", "wrongpassword").
			Return(nil, errors.New("invalid credentials")).Once()

		token, err := authenticator.Login(ctx, "bad@example.com", "wrongpassword")

		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "unauthorized")
	})

	t.Run("Failed login - identity not found", func(t *testing.T) {
		mockProvider.On("VerifyIdentity", ctx, "unknown@example.com", "password123").
			Return(nil, auth.ErrIdentityNotFound).Once()

		token, err := authenticator.Login(ctx, "unknown@example.com", "password123")

		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "unauthorized")
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
		}

		mockProvider.On("FindIdentityByIdentifier", ctx, "admin@example.com").
			Return(identity, nil).Once()

		token, err := authenticator.Impersonate(ctx, "admin@example.com")

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token can be parsed and contains correct claims
		parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
			return []byte("test-signing-key"), nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		assert.True(t, ok)
		assert.Equal(t, identity.ID(), claims["sub"])
		assert.Equal(t, "test-issuer", claims["iss"])
		assert.Equal(t, []any{"test:audience"}, claims["aud"])

		// Verify role is in the data claims
		datClaims, ok := claims["dat"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "admin", datClaims["role"])
	})

	t.Run("Failed impersonation - identity not found", func(t *testing.T) {
		mockProvider.On("FindIdentityByIdentifier", ctx, "unknown@example.com").
			Return(nil, auth.ErrIdentityNotFound).Once()

		token, err := authenticator.Impersonate(ctx, "unknown@example.com")

		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "unauthorized")
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

	// create a valid token for testing
	now := time.Now()
	userID := uuid.New().String()
	expiry := now.Add(24 * time.Hour)

	claims := jwt.MapClaims{
		"sub": userID,
		"aud": []string{"test:audience"},
		"iss": "test-issuer",
		"iat": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(expiry),
		"dat": map[string]any{
			"role": "admin",
		},
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
		// create an expired token
		expiredClaims := jwt.MapClaims{
			"sub": userID,
			"aud": []string{"test:audience"},
			"iss": "test-issuer",
			"iat": jwt.NewNumericDate(now.Add(-48 * time.Hour)),
			"exp": jwt.NewNumericDate(now.Add(-24 * time.Hour)),
			"dat": map[string]any{
				"role": "admin",
			},
		}

		expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
		expiredTokenString, _ := expiredToken.SignedString([]byte("test-signing-key"))

		session, err := authenticator.SessionFromToken(expiredTokenString)

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "token")
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
		assert.Contains(t, err.Error(), "unauthorized")
	})
}
