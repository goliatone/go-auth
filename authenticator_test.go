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
)

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
		assert.Contains(t, err.Error(), "identity not found")
	})
}

func TestGenerateEnhancedJWT(t *testing.T) {
	// Setup test environment
	mockProvider := new(MockIdentityProvider)
	mockConfig := new(MockConfig)

	// Configure mock config
	mockConfig.On("GetSigningKey").Return("test-signing-key")
	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetIssuer").Return("test-issuer")
	mockConfig.On("GetAudience").Return([]string{"test:audience"})

	// Create authenticator
	authenticator := auth.NewAuthenticator(mockProvider, mockConfig)

	t.Run("Successful enhanced JWT generation", func(t *testing.T) {
		identity := TestIdentity{
			id:       uuid.New().String(),
			username: "testuser",
			email:    "test@example.com",
			role:     "admin",
		}

		resourceRoles := map[string]string{
			"project:123": "owner",
			"project:456": "member",
		}

		token, err := authenticator.GenerateEnhancedJWT(identity, resourceRoles)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token can be parsed and contains correct structured claims
		parsedToken, err := jwt.ParseWithClaims(token, &auth.JWTClaims{}, func(t *jwt.Token) (any, error) {
			return []byte("test-signing-key"), nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		claims, ok := parsedToken.Claims.(*auth.JWTClaims)
		assert.True(t, ok)

		// Verify registered claims
		assert.Equal(t, identity.ID(), claims.Subject())
		assert.Equal(t, "test-issuer", claims.Issuer)
		assert.Equal(t, jwt.ClaimStrings{"test:audience"}, claims.Audience)
		assert.NotNil(t, claims.IssuedAt)
		assert.NotNil(t, claims.ExpiresAt)

		// Verify custom claims
		assert.Equal(t, identity.ID(), claims.UID)
		assert.Equal(t, "admin", claims.UserRole)
		assert.Equal(t, resourceRoles, claims.Resources)

		// Test AuthClaims interface methods
		assert.Equal(t, identity.ID(), claims.Subject())
		assert.Equal(t, identity.ID(), claims.UserID())
		assert.Equal(t, "admin", claims.Role())

		// Test role checking methods
		assert.True(t, claims.HasRole("admin"))
		assert.False(t, claims.HasRole("guest"))
		assert.True(t, claims.HasRole("owner"))  // should find in resources
		assert.True(t, claims.HasRole("member")) // should find in resources

		// Test IsAtLeast method
		assert.True(t, claims.IsAtLeast(string(auth.RoleGuest)))
		assert.True(t, claims.IsAtLeast(string(auth.RoleMember)))
		assert.True(t, claims.IsAtLeast(string(auth.RoleAdmin)))
		assert.False(t, claims.IsAtLeast(string(auth.RoleOwner)))

		// Test permission methods with global role fallback
		assert.True(t, claims.CanRead("unknown:resource"))    // admin can read
		assert.True(t, claims.CanEdit("unknown:resource"))    // admin can edit
		assert.True(t, claims.CanCreate("unknown:resource"))  // admin can create
		assert.False(t, claims.CanDelete("unknown:resource")) // admin cannot delete (only owner can)

		// Test permission methods with resource-specific roles
		assert.True(t, claims.CanRead("project:123"))   // owner can read
		assert.True(t, claims.CanEdit("project:123"))   // owner can edit
		assert.True(t, claims.CanCreate("project:123")) // owner can create
		assert.True(t, claims.CanDelete("project:123")) // owner can delete

		assert.True(t, claims.CanRead("project:456"))    // member can read
		assert.True(t, claims.CanEdit("project:456"))    // member can edit
		assert.False(t, claims.CanCreate("project:456")) // member cannot create
		assert.False(t, claims.CanDelete("project:456")) // member cannot delete

		// Test time methods
		assert.False(t, claims.IssuedAt().IsZero())
		assert.False(t, claims.Expires().IsZero())
		assert.True(t, claims.Expires().After(claims.IssuedAt()))
	})

	t.Run("Enhanced JWT with empty resource roles", func(t *testing.T) {
		identity := TestIdentity{
			id:       uuid.New().String(),
			username: "testuser",
			email:    "test@example.com",
			role:     "member",
		}

		token, err := authenticator.GenerateEnhancedJWT(identity, nil)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token can be parsed
		parsedToken, err := jwt.ParseWithClaims(token, &auth.JWTClaims{}, func(t *jwt.Token) (any, error) {
			return []byte("test-signing-key"), nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		claims, ok := parsedToken.Claims.(*auth.JWTClaims)
		assert.True(t, ok)

		// Verify structure
		assert.Equal(t, identity.ID(), claims.UID)
		assert.Equal(t, "member", claims.UserRole)
		assert.Nil(t, claims.Resources)

		// Test permissions fall back to global role
		assert.True(t, claims.CanRead("any:resource"))    // member can read
		assert.True(t, claims.CanEdit("any:resource"))    // member can edit
		assert.False(t, claims.CanCreate("any:resource")) // member cannot create
		assert.False(t, claims.CanDelete("any:resource")) // member cannot delete
	})

	t.Run("Enhanced JWT with guest role", func(t *testing.T) {
		identity := TestIdentity{
			id:       uuid.New().String(),
			username: "guestuser",
			email:    "guest@example.com",
			role:     "guest",
		}

		resourceRoles := map[string]string{
			"public:resource": "guest",
		}

		token, err := authenticator.GenerateEnhancedJWT(identity, resourceRoles)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token can be parsed
		parsedToken, err := jwt.ParseWithClaims(token, &auth.JWTClaims{}, func(t *jwt.Token) (any, error) {
			return []byte("test-signing-key"), nil
		})

		assert.NoError(t, err)
		claims, ok := parsedToken.Claims.(*auth.JWTClaims)
		assert.True(t, ok)

		// Test guest permissions
		assert.True(t, claims.CanRead("any:resource"))    // guest can read
		assert.False(t, claims.CanEdit("any:resource"))   // guest cannot edit
		assert.False(t, claims.CanCreate("any:resource")) // guest cannot create
		assert.False(t, claims.CanDelete("any:resource")) // guest cannot delete

		// Test IsAtLeast for guest
		assert.True(t, claims.IsAtLeast(string(auth.RoleGuest)))
		assert.False(t, claims.IsAtLeast(string(auth.RoleMember)))
		assert.False(t, claims.IsAtLeast(string(auth.RoleAdmin)))
		assert.False(t, claims.IsAtLeast(string(auth.RoleOwner)))
	})
}
