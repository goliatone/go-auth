package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-auth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestSessionObject(t *testing.T) {
	userID := uuid.New().String()
	now := time.Now()
	sessionData := map[string]any{
		"role": "admin",
	}

	session := &auth.SessionObject{
		UserID:         userID,
		Audience:       []string{"app:user"},
		Issuer:         "test-issuer",
		IssuedAt:       &now,
		ExpirationDate: &now,
		Data:           sessionData,
	}

	// Test GetUserID
	assert.Equal(t, userID, session.GetUserID())

	// Test GetUserUUID
	userUUID, err := session.GetUserUUID()
	assert.NoError(t, err)
	assert.Equal(t, userID, userUUID.String())

	// Test GetAudience
	assert.Equal(t, []string{"app:user"}, session.GetAudience())

	// Test GetIssuer
	assert.Equal(t, "test-issuer", session.GetIssuer())

	// Test GetIssuedAt
	assert.Equal(t, &now, session.GetIssuedAt())

	// Test GetData
	assert.Equal(t, sessionData, session.GetData())

	// Test String method
	stringRep := session.String()
	assert.Contains(t, stringRep, userID)
	assert.Contains(t, stringRep, "app:user")
	assert.Contains(t, stringRep, "test-issuer")
}

func TestSessionFromClaims(t *testing.T) {
	userID := uuid.New().String()
	now := time.Now()
	expTime := now.Add(time.Hour)

	// Create valid JWT claims
	claims := jwt.MapClaims{
		"sub": userID,
		"aud": []string{"test:audience"},
		"iss": "test-issuer",
		"iat": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(expTime),
		"dat": map[string]any{
			"role": "admin",
		},
	}

	// Test with a mock function to access the unexported sessionFromClaims
	// In a real test, you might need to expose this function or test it indirectly
	auther := createTestAuthenticator(t)

	// Create a token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("test-signing-key"))
	assert.NoError(t, err)

	// Get session from token
	session, err := auther.SessionFromToken(tokenString)
	assert.NoError(t, err)

	// Verify session attributes
	assert.Equal(t, userID, session.GetUserID())
	assert.Equal(t, []string{"test:audience"}, session.GetAudience())
	assert.Equal(t, "test-issuer", session.GetIssuer())

	// Verify data exists and contains the role
	data := session.GetData()
	assert.NotNil(t, data)
	assert.Equal(t, "admin", data["role"])
}

// Helper function to create a test authenticator
func createTestAuthenticator(_ *testing.T) auth.Authenticator {
	// Create a mock identity provider
	provider := &mockIdentityProvider{}

	// Create config with minimal settings
	cfg := &mockConfig{
		signingKey: "test-signing-key",
		tokenExp:   24,
		audience:   []string{"test:audience"},
		issuer:     "test-issuer",
	}

	return auth.NewAuthenticator(provider, cfg)
}

// Mock implementations for testing

type mockIdentityProvider struct{}

func (m *mockIdentityProvider) VerifyIdentity(ctx context.Context, identifier, password string) (auth.Identity, error) {
	return &mockIdentity{
		id:       uuid.New().String(),
		username: "testuser",
		email:    "test@example.com",
		role:     "admin",
	}, nil
}

func (m *mockIdentityProvider) FindIdentityByIdentifier(ctx context.Context, identifier string) (auth.Identity, error) {
	return &mockIdentity{
		id:       identifier,
		username: "testuser",
		email:    "test@example.com",
		role:     "admin",
	}, nil
}

type mockIdentity struct {
	id       string
	username string
	email    string
	role     string
}

func (m *mockIdentity) ID() string       { return m.id }
func (m *mockIdentity) Username() string { return m.username }
func (m *mockIdentity) Email() string    { return m.email }
func (m *mockIdentity) Role() string     { return m.role }

type mockConfig struct {
	signingKey string
	tokenExp   int
	audience   []string
	issuer     string
}

func (m *mockConfig) GetSigningKey() string           { return m.signingKey }
func (m *mockConfig) GetSigningMethod() string        { return "HS256" }
func (m *mockConfig) GetContextKey() string           { return "jwt" }
func (m *mockConfig) GetTokenExpiration() int         { return m.tokenExp }
func (m *mockConfig) GetExtendedTokenDuration() int   { return m.tokenExp * 2 }
func (m *mockConfig) GetTokenLookup() string          { return "header:Authorization" }
func (m *mockConfig) GetAuthScheme() string           { return "Bearer" }
func (m *mockConfig) GetIssuer() string               { return m.issuer }
func (m *mockConfig) GetAudience() []string           { return m.audience }
func (m *mockConfig) GetRejectedRouteKey() string     { return "rejected_route" }
func (m *mockConfig) GetRejectedRouteDefault() string { return "/login" }
