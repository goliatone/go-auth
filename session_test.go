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
