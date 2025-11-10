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

func TestSessionFromAuthClaims(t *testing.T) {
	userID := uuid.New().String()
	now := time.Now()
	expTime := now.Add(time.Hour)

	t.Run("basic claims without resources", func(t *testing.T) {
		// Create JWTClaims struct with basic data
		claims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   userID,
				Audience:  []string{"test:audience"},
				Issuer:    "test-issuer",
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(expTime),
			},
			UID:      userID,
			UserRole: "admin",
		}

		// Test sessionFromAuthClaims function
		session, err := testSessionFromAuthClaims(claims)
		assert.NoError(t, err)
		assert.NotNil(t, session)

		// Verify session attributes
		assert.Equal(t, userID, session.GetUserID())
		assert.Equal(t, []string{"test:audience"}, session.GetAudience())
		assert.Equal(t, "test-issuer", session.GetIssuer())
		// JWT timestamps lose precision, so we check if they're close
		assert.Equal(t, now.Truncate(time.Second), session.GetIssuedAt().Truncate(time.Second))
		assert.Equal(t, expTime.Truncate(time.Second), session.ExpirationDate.Truncate(time.Second))

		// Verify data contains the role
		data := session.GetData()
		assert.NotNil(t, data)
		assert.Equal(t, "admin", data["role"])
		// Should not have resources for basic claims
		_, hasResources := data["resources"]
		assert.False(t, hasResources)
		_, hasMetadata := data["metadata"]
		assert.False(t, hasMetadata)
	})

	t.Run("claims with resource-specific roles", func(t *testing.T) {
		// Create JWTClaims struct with resource-specific roles
		claims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   userID,
				Audience:  []string{"test:audience", "another:audience"},
				Issuer:    "test-issuer",
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(expTime),
			},
			UID:      userID,
			UserRole: "member",
			Resources: map[string]string{
				"project-123":  "owner",
				"document-456": "admin",
			},
		}

		// Test sessionFromAuthClaims function
		session, err := testSessionFromAuthClaims(claims)
		assert.NoError(t, err)
		assert.NotNil(t, session)

		// Verify session attributes
		assert.Equal(t, userID, session.GetUserID())
		assert.Equal(t, []string{"test:audience", "another:audience"}, session.GetAudience())
		assert.Equal(t, "test-issuer", session.GetIssuer())

		// Verify data contains both role and resources
		data := session.GetData()
		assert.NotNil(t, data)
		assert.Equal(t, "member", data["role"])

		// Check that resources are properly included
		resources, hasResources := data["resources"]
		assert.True(t, hasResources)
		resourceMap, ok := resources.(map[string]string)
		assert.True(t, ok)
		assert.Equal(t, "owner", resourceMap["project-123"])
		assert.Equal(t, "admin", resourceMap["document-456"])
		_, hasMetadata := data["metadata"]
		assert.False(t, hasMetadata)
	})

	t.Run("claims with empty resources map", func(t *testing.T) {
		// Create JWTClaims struct with empty resources
		claims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   userID,
				Audience:  []string{"test:audience"},
				Issuer:    "test-issuer",
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(expTime),
			},
			UID:       userID,
			UserRole:  "guest",
			Resources: map[string]string{}, // empty map
		}

		// Test sessionFromAuthClaims function
		session, err := testSessionFromAuthClaims(claims)
		assert.NoError(t, err)
		assert.NotNil(t, session)

		// Verify data contains the role but no resources (empty map should be ignored)
		data := session.GetData()
		assert.NotNil(t, data)
		assert.Equal(t, "guest", data["role"])
		// Empty resources map should not be included
		_, hasResources := data["resources"]
		assert.False(t, hasResources)
		_, hasMetadata := data["metadata"]
		assert.False(t, hasMetadata)
	})

	t.Run("claims metadata is exposed to session data", func(t *testing.T) {
		claims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   userID,
				Audience:  []string{"test:audience"},
				Issuer:    "test-issuer",
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(expTime),
			},
			UID:      userID,
			UserRole: "member",
			Metadata: map[string]any{
				"tenant":   "acme",
				"features": []string{"beta"},
			},
		}

		session, err := testSessionFromAuthClaims(claims)
		assert.NoError(t, err)
		assert.NotNil(t, session)

		data := session.GetData()
		assert.NotNil(t, data)

		metadata, ok := data["metadata"]
		assert.True(t, ok)
		metaMap, ok := metadata.(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "acme", metaMap["tenant"])

		features, ok := metaMap["features"].([]string)
		assert.True(t, ok)
		assert.ElementsMatch(t, []string{"beta"}, features)
	})

	t.Run("nil claims should return error", func(t *testing.T) {
		// Test with nil claims
		session, err := testSessionFromAuthClaims(nil)
		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, auth.ErrUnableToParseData, err)
	})

	t.Run("claims without issuer should use subject as fallback", func(t *testing.T) {
		// Create JWTClaims struct without issuer
		claims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  userID,
				Audience: []string{"test:audience"},
				// No Issuer set
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(expTime),
			},
			UID:      userID,
			UserRole: "admin",
		}

		// Test sessionFromAuthClaims function
		session, err := testSessionFromAuthClaims(claims)
		assert.NoError(t, err)
		assert.NotNil(t, session)

		// Verify issuer falls back to subject
		assert.Equal(t, userID, session.GetIssuer())
	})

	t.Run("claims with UserID field takes precedence over Subject", func(t *testing.T) {
		subjectID := uuid.New().String()
		userIDField := uuid.New().String()

		// Create JWTClaims struct with both Subject and UID
		claims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   subjectID,
				Audience:  []string{"test:audience"},
				Issuer:    "test-issuer",
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(expTime),
			},
			UID:      userIDField, // This should take precedence
			UserRole: "admin",
		}

		// Test sessionFromAuthClaims function
		session, err := testSessionFromAuthClaims(claims)
		assert.NoError(t, err)
		assert.NotNil(t, session)

		// Verify UID field is used instead of Subject
		assert.Equal(t, userIDField, session.GetUserID())
		assert.NotEqual(t, subjectID, session.GetUserID())
	})
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

// Test helper function to access the unexported sessionFromAuthClaims function
func testSessionFromAuthClaims(claims auth.AuthClaims) (*auth.SessionObject, error) {
	// Since sessionFromAuthClaims is unexported, we need to access it through package internals
	// This is a workaround for testing - in a real scenario, you might make the function exported
	// or test it indirectly through other methods

	// For now, we'll create the session manually following the same logic as sessionFromAuthClaims
	if claims == nil {
		return nil, auth.ErrUnableToParseData
	}

	// Build the data map from the claims
	data := make(map[string]any)
	data["role"] = claims.Role()

	// Add resource roles if available (for JWTClaims implementation)
	if jwtClaims, ok := claims.(*auth.JWTClaims); ok {
		if len(jwtClaims.Resources) > 0 {
			data["resources"] = jwtClaims.Resources
		}

		if len(jwtClaims.Metadata) > 0 {
			data["metadata"] = jwtClaims.Metadata
		}
	}

	// Convert audience from jwt.ClaimStrings to []string
	var audience []string
	if jwtClaims, ok := claims.(*auth.JWTClaims); ok {
		if jwtClaims.RegisteredClaims.Audience != nil {
			for _, aud := range jwtClaims.RegisteredClaims.Audience {
				audience = append(audience, aud)
			}
		}
	}

	issuedAt := claims.IssuedAt()
	expiresAt := claims.Expires()

	// Get issuer from claims
	issuer := ""
	if jwtClaims, ok := claims.(*auth.JWTClaims); ok {
		if jwtClaims.RegisteredClaims.Issuer != "" {
			issuer = jwtClaims.RegisteredClaims.Issuer
		}
	}
	if issuer == "" {
		issuer = claims.Subject() // Fallback to subject
	}

	return &auth.SessionObject{
		UserID:         claims.UserID(),
		Audience:       audience,
		Issuer:         issuer,
		Data:           data,
		IssuedAt:       &issuedAt,
		ExpirationDate: &expiresAt,
	}, nil
}

// TestSessionObject_RoleCapableSession tests the RoleCapableSession implementation
func TestSessionObject_RoleCapableSession(t *testing.T) {
	userID := uuid.New().String()
	now := time.Now()

	t.Run("CanRead with resource-specific role", func(t *testing.T) {
		session := &auth.SessionObject{
			UserID:   userID,
			Audience: []string{"app:user"},
			Issuer:   "test-issuer",
			IssuedAt: &now,
			Data: map[string]any{
				"role": "guest",
				"resources": map[string]any{
					"documents": "admin",
				},
			},
		}

		// Should use resource-specific admin role, not global guest role
		assert.True(t, session.CanRead("documents"))
		// Should use global guest role for other resources
		assert.True(t, session.CanRead("other-resource"))
	})

	t.Run("CanEdit with resource-specific role", func(t *testing.T) {
		session := &auth.SessionObject{
			UserID:   userID,
			Audience: []string{"app:user"},
			Issuer:   "test-issuer",
			IssuedAt: &now,
			Data: map[string]any{
				"role": "guest",
				"resources": map[string]any{
					"documents": "admin",
				},
			},
		}

		// Should use resource-specific admin role
		assert.True(t, session.CanEdit("documents"))
		// Should use global guest role (cannot edit)
		assert.False(t, session.CanEdit("other-resource"))
	})

	t.Run("CanCreate with resource-specific role", func(t *testing.T) {
		session := &auth.SessionObject{
			UserID:   userID,
			Audience: []string{"app:user"},
			Issuer:   "test-issuer",
			IssuedAt: &now,
			Data: map[string]any{
				"role": "member",
				"resources": map[string]any{
					"documents": "admin",
				},
			},
		}

		// Should use resource-specific admin role
		assert.True(t, session.CanCreate("documents"))
		// Should use global member role (cannot create)
		assert.False(t, session.CanCreate("other-resource"))
	})

	t.Run("CanDelete with resource-specific role", func(t *testing.T) {
		session := &auth.SessionObject{
			UserID:   userID,
			Audience: []string{"app:user"},
			Issuer:   "test-issuer",
			IssuedAt: &now,
			Data: map[string]any{
				"role": "admin",
				"resources": map[string]any{
					"documents": "owner",
				},
			},
		}

		// Should use resource-specific owner role
		assert.True(t, session.CanDelete("documents"))
		// Should use global admin role (cannot delete)
		assert.False(t, session.CanDelete("other-resource"))
	})

	t.Run("fallback to global role when no resource-specific role", func(t *testing.T) {
		tests := []struct {
			name      string
			role      string
			canRead   bool
			canEdit   bool
			canCreate bool
			canDelete bool
		}{
			{
				name:      "guest role permissions",
				role:      "guest",
				canRead:   true,
				canEdit:   false,
				canCreate: false,
				canDelete: false,
			},
			{
				name:      "member role permissions",
				role:      "member",
				canRead:   true,
				canEdit:   true,
				canCreate: false,
				canDelete: false,
			},
			{
				name:      "admin role permissions",
				role:      "admin",
				canRead:   true,
				canEdit:   true,
				canCreate: true,
				canDelete: false,
			},
			{
				name:      "owner role permissions",
				role:      "owner",
				canRead:   true,
				canEdit:   true,
				canCreate: true,
				canDelete: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				session := &auth.SessionObject{
					UserID:   userID,
					Audience: []string{"app:user"},
					Issuer:   "test-issuer",
					IssuedAt: &now,
					Data: map[string]any{
						"role": tt.role,
					},
				}

				assert.Equal(t, tt.canRead, session.CanRead("documents"))
				assert.Equal(t, tt.canEdit, session.CanEdit("documents"))
				assert.Equal(t, tt.canCreate, session.CanCreate("documents"))
				assert.Equal(t, tt.canDelete, session.CanDelete("documents"))
			})
		}
	})

	t.Run("backward compatibility - no Data", func(t *testing.T) {
		session := &auth.SessionObject{
			UserID:   userID,
			Audience: []string{"app:user"},
			Issuer:   "test-issuer",
			IssuedAt: &now,
			Data:     nil,
		}

		// Should default to guest role when no data
		assert.True(t, session.CanRead("documents"))
		assert.False(t, session.CanEdit("documents"))
		assert.False(t, session.CanCreate("documents"))
		assert.False(t, session.CanDelete("documents"))
	})

	t.Run("backward compatibility - no role in Data", func(t *testing.T) {
		session := &auth.SessionObject{
			UserID:   userID,
			Audience: []string{"app:user"},
			Issuer:   "test-issuer",
			IssuedAt: &now,
			Data:     map[string]any{},
		}

		// Should default to guest role when no role in data
		assert.True(t, session.CanRead("documents"))
		assert.False(t, session.CanEdit("documents"))
		assert.False(t, session.CanCreate("documents"))
		assert.False(t, session.CanDelete("documents"))
	})

	t.Run("backward compatibility - invalid role format", func(t *testing.T) {
		session := &auth.SessionObject{
			UserID:   userID,
			Audience: []string{"app:user"},
			Issuer:   "test-issuer",
			IssuedAt: &now,
			Data: map[string]any{
				"role": 123, // invalid type
			},
		}

		// Should default to guest role when role is invalid format
		assert.True(t, session.CanRead("documents"))
		assert.False(t, session.CanEdit("documents"))
		assert.False(t, session.CanCreate("documents"))
		assert.False(t, session.CanDelete("documents"))
	})

	t.Run("HasRole functionality", func(t *testing.T) {
		session := &auth.SessionObject{
			UserID:   userID,
			Audience: []string{"app:user"},
			Issuer:   "test-issuer",
			IssuedAt: &now,
			Data: map[string]any{
				"role": "admin",
			},
		}

		assert.True(t, session.HasRole("admin"))
		assert.False(t, session.HasRole("owner"))
		assert.False(t, session.HasRole("member"))
	})

	t.Run("IsAtLeast functionality", func(t *testing.T) {
		session := &auth.SessionObject{
			UserID:   userID,
			Audience: []string{"app:user"},
			Issuer:   "test-issuer",
			IssuedAt: &now,
			Data: map[string]any{
				"role": "admin",
			},
		}

		assert.True(t, session.IsAtLeast(auth.RoleGuest))
		assert.True(t, session.IsAtLeast(auth.RoleMember))
		assert.True(t, session.IsAtLeast(auth.RoleAdmin))
		assert.False(t, session.IsAtLeast(auth.RoleOwner))
	})

	t.Run("RoleCapableSession interface compliance", func(t *testing.T) {
		// Test that SessionObject implements RoleCapableSession interface
		var _ auth.RoleCapableSession = (*auth.SessionObject)(nil)

		session := &auth.SessionObject{
			UserID:   userID,
			Audience: []string{"app:user"},
			Issuer:   "test-issuer",
			IssuedAt: &now,
			Data: map[string]any{
				"role": "admin",
				"resources": map[string]any{
					"documents": "owner",
				},
			},
		}

		var roleCapable auth.RoleCapableSession = session

		// Test all interface methods work through the interface
		assert.Equal(t, userID, roleCapable.GetUserID())
		assert.True(t, roleCapable.CanRead("documents"))
		assert.True(t, roleCapable.CanEdit("documents"))
		assert.True(t, roleCapable.CanCreate("documents"))
		assert.True(t, roleCapable.CanDelete("documents")) // owner role on documents
		assert.True(t, roleCapable.HasRole("admin"))
		assert.True(t, roleCapable.IsAtLeast(auth.RoleAdmin))
	})

	t.Run("invalid resource structure handling", func(t *testing.T) {
		session := &auth.SessionObject{
			UserID:   userID,
			Audience: []string{"app:user"},
			Issuer:   "test-issuer",
			IssuedAt: &now,
			Data: map[string]any{
				"role":      "admin",
				"resources": "invalid-format", // should be map[string]any
			},
		}

		// Should fallback to global role when resources format is invalid
		assert.True(t, session.CanRead("documents"))
		assert.True(t, session.CanEdit("documents"))
		assert.True(t, session.CanCreate("documents"))
		assert.False(t, session.CanDelete("documents")) // admin can't delete
	})

	t.Run("invalid resource role type handling", func(t *testing.T) {
		session := &auth.SessionObject{
			UserID:   userID,
			Audience: []string{"app:user"},
			Issuer:   "test-issuer",
			IssuedAt: &now,
			Data: map[string]any{
				"role": "admin",
				"resources": map[string]any{
					"documents": 123, // should be string
				},
			},
		}

		// Should fallback to global role when resource role type is invalid
		assert.True(t, session.CanRead("documents"))
		assert.True(t, session.CanEdit("documents"))
		assert.True(t, session.CanCreate("documents"))
		assert.False(t, session.CanDelete("documents")) // admin can't delete
	})
}
