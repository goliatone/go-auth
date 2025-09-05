package auth_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-auth"
	"github.com/stretchr/testify/assert"
)

func TestJWTClaims_Subject(t *testing.T) {
	claims := &auth.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user123",
		},
	}

	assert.Equal(t, "user123", claims.Subject())
}

func TestJWTClaims_UserID(t *testing.T) {
	t.Run("returns UID when present", func(t *testing.T) {
		claims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "user123",
			},
			UID: "uid456",
		}

		assert.Equal(t, "uid456", claims.UserID())
	})

	t.Run("fallback to subject when UID is empty", func(t *testing.T) {
		claims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "user123",
			},
		}

		assert.Equal(t, "user123", claims.UserID())
	})
}

func TestJWTClaims_Role(t *testing.T) {
	claims := &auth.JWTClaims{
		UserRole: "admin",
	}

	assert.Equal(t, "admin", claims.Role())
}

func TestJWTClaims_CanRead(t *testing.T) {
	tests := []struct {
		name        string
		userRole    string
		resources   map[string]string
		resource    string
		expected    bool
		description string
	}{
		{
			name:        "resource-specific role allows read",
			userRole:    "guest",
			resources:   map[string]string{"documents": "admin"},
			resource:    "documents",
			expected:    true,
			description: "should use resource-specific admin role instead of global guest",
		},
		{
			name:        "resource-specific role denies read",
			userRole:    "admin",
			resources:   map[string]string{},
			resource:    "documents",
			expected:    true,
			description: "should fallback to global admin role when no resource-specific role",
		},
		{
			name:        "global role allows read for all roles",
			userRole:    "guest",
			resources:   nil,
			resource:    "documents",
			expected:    true,
			description: "guest role should be able to read",
		},
		{
			name:        "global role allows read for member",
			userRole:    "member",
			resources:   nil,
			resource:    "documents",
			expected:    true,
			description: "member role should be able to read",
		},
		{
			name:        "global role allows read for admin",
			userRole:    "admin",
			resources:   nil,
			resource:    "documents",
			expected:    true,
			description: "admin role should be able to read",
		},
		{
			name:        "global role allows read for owner",
			userRole:    "owner",
			resources:   nil,
			resource:    "documents",
			expected:    true,
			description: "owner role should be able to read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &auth.JWTClaims{
				UserRole:  tt.userRole,
				Resources: tt.resources,
			}

			result := claims.CanRead(tt.resource)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestJWTClaims_CanEdit(t *testing.T) {
	tests := []struct {
		name        string
		userRole    string
		resources   map[string]string
		resource    string
		expected    bool
		description string
	}{
		{
			name:        "resource-specific admin role allows edit",
			userRole:    "guest",
			resources:   map[string]string{"documents": "admin"},
			resource:    "documents",
			expected:    true,
			description: "should use resource-specific admin role",
		},
		{
			name:        "guest cannot edit",
			userRole:    "guest",
			resources:   nil,
			resource:    "documents",
			expected:    false,
			description: "guest role should not be able to edit",
		},
		{
			name:        "member can edit",
			userRole:    "member",
			resources:   nil,
			resource:    "documents",
			expected:    true,
			description: "member role should be able to edit",
		},
		{
			name:        "admin can edit",
			userRole:    "admin",
			resources:   nil,
			resource:    "documents",
			expected:    true,
			description: "admin role should be able to edit",
		},
		{
			name:        "owner can edit",
			userRole:    "owner",
			resources:   nil,
			resource:    "documents",
			expected:    true,
			description: "owner role should be able to edit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &auth.JWTClaims{
				UserRole:  tt.userRole,
				Resources: tt.resources,
			}

			result := claims.CanEdit(tt.resource)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestJWTClaims_CanCreate(t *testing.T) {
	tests := []struct {
		name        string
		userRole    string
		resources   map[string]string
		resource    string
		expected    bool
		description string
	}{
		{
			name:        "guest cannot create",
			userRole:    "guest",
			resources:   nil,
			resource:    "documents",
			expected:    false,
			description: "guest role should not be able to create",
		},
		{
			name:        "member cannot create",
			userRole:    "member",
			resources:   nil,
			resource:    "documents",
			expected:    false,
			description: "member role should not be able to create",
		},
		{
			name:        "admin can create",
			userRole:    "admin",
			resources:   nil,
			resource:    "documents",
			expected:    true,
			description: "admin role should be able to create",
		},
		{
			name:        "owner can create",
			userRole:    "owner",
			resources:   nil,
			resource:    "documents",
			expected:    true,
			description: "owner role should be able to create",
		},
		{
			name:        "resource-specific admin role allows create",
			userRole:    "guest",
			resources:   map[string]string{"documents": "admin"},
			resource:    "documents",
			expected:    true,
			description: "should use resource-specific admin role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &auth.JWTClaims{
				UserRole:  tt.userRole,
				Resources: tt.resources,
			}

			result := claims.CanCreate(tt.resource)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestJWTClaims_CanDelete(t *testing.T) {
	tests := []struct {
		name        string
		userRole    string
		resources   map[string]string
		resource    string
		expected    bool
		description string
	}{
		{
			name:        "guest cannot delete",
			userRole:    "guest",
			resources:   nil,
			resource:    "documents",
			expected:    false,
			description: "guest role should not be able to delete",
		},
		{
			name:        "member cannot delete",
			userRole:    "member",
			resources:   nil,
			resource:    "documents",
			expected:    false,
			description: "member role should not be able to delete",
		},
		{
			name:        "admin cannot delete",
			userRole:    "admin",
			resources:   nil,
			resource:    "documents",
			expected:    false,
			description: "admin role should not be able to delete",
		},
		{
			name:        "owner can delete",
			userRole:    "owner",
			resources:   nil,
			resource:    "documents",
			expected:    true,
			description: "owner role should be able to delete",
		},
		{
			name:        "resource-specific owner role allows delete",
			userRole:    "guest",
			resources:   map[string]string{"documents": "owner"},
			resource:    "documents",
			expected:    true,
			description: "should use resource-specific owner role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &auth.JWTClaims{
				UserRole:  tt.userRole,
				Resources: tt.resources,
			}

			result := claims.CanDelete(tt.resource)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestJWTClaims_HasRole(t *testing.T) {
	tests := []struct {
		name        string
		userRole    string
		resources   map[string]string
		checkRole   string
		expected    bool
		description string
	}{
		{
			name:        "has global role",
			userRole:    "admin",
			resources:   nil,
			checkRole:   "admin",
			expected:    true,
			description: "should match global role",
		},
		{
			name:        "does not have global role",
			userRole:    "member",
			resources:   nil,
			checkRole:   "admin",
			expected:    false,
			description: "should not match different global role",
		},
		{
			name:        "has role in resources",
			userRole:    "guest",
			resources:   map[string]string{"documents": "admin"},
			checkRole:   "admin",
			expected:    true,
			description: "should match resource-specific role",
		},
		{
			name:        "does not have role anywhere",
			userRole:    "guest",
			resources:   map[string]string{"documents": "member"},
			checkRole:   "admin",
			expected:    false,
			description: "should not match when role not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &auth.JWTClaims{
				UserRole:  tt.userRole,
				Resources: tt.resources,
			}

			result := claims.HasRole(tt.checkRole)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestJWTClaims_IsAtLeast(t *testing.T) {
	tests := []struct {
		name        string
		userRole    string
		minRole     string
		expected    bool
		description string
	}{
		{
			name:        "owner is at least admin",
			userRole:    "owner",
			minRole:     "admin",
			expected:    true,
			description: "owner should meet admin requirement",
		},
		{
			name:        "admin is at least admin",
			userRole:    "admin",
			minRole:     "admin",
			expected:    true,
			description: "admin should meet admin requirement",
		},
		{
			name:        "member is not at least admin",
			userRole:    "member",
			minRole:     "admin",
			expected:    false,
			description: "member should not meet admin requirement",
		},
		{
			name:        "guest is not at least member",
			userRole:    "guest",
			minRole:     "member",
			expected:    false,
			description: "guest should not meet member requirement",
		},
		{
			name:        "member is at least guest",
			userRole:    "member",
			minRole:     "guest",
			expected:    true,
			description: "member should meet guest requirement",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &auth.JWTClaims{
				UserRole: tt.userRole,
			}

			result := claims.IsAtLeast(tt.minRole)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestJWTClaims_Expires(t *testing.T) {
	t.Run("returns expiration time when set", func(t *testing.T) {
		expTime := time.Now().Add(time.Hour)
		claims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expTime),
			},
		}

		result := claims.Expires()
		assert.WithinDuration(t, expTime, result, time.Second)
	})

	t.Run("returns zero time when not set", func(t *testing.T) {
		claims := &auth.JWTClaims{}

		result := claims.Expires()
		assert.True(t, result.IsZero())
	})
}

func TestJWTClaims_IssuedAt(t *testing.T) {
	t.Run("returns issued at time when set", func(t *testing.T) {
		issuedTime := time.Now()
		claims := &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(issuedTime),
			},
		}

		result := claims.IssuedAt()
		assert.WithinDuration(t, issuedTime, result, time.Second)
	})

	t.Run("returns zero time when not set", func(t *testing.T) {
		claims := &auth.JWTClaims{}

		result := claims.IssuedAt()
		assert.True(t, result.IsZero())
	})
}

func TestJWTClaims_AuthClaimsInterface(t *testing.T) {
	// Test that JWTClaims implements AuthClaims interface
	var _ auth.AuthClaims = (*auth.JWTClaims)(nil)

	// Create a JWTClaims instance and verify it can be used as AuthClaims
	now := time.Now()
	claims := &auth.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
		UID:       "uid456",
		UserRole:  "admin",
		Resources: map[string]string{"documents": "owner"},
	}

	var authClaims auth.AuthClaims = claims

	// Test all interface methods work through the interface
	assert.Equal(t, "user123", authClaims.Subject())
	assert.Equal(t, "uid456", authClaims.UserID())
	assert.Equal(t, "admin", authClaims.Role())
	assert.True(t, authClaims.CanRead("documents"))
	assert.True(t, authClaims.CanEdit("documents"))
	assert.True(t, authClaims.CanCreate("documents"))
	assert.True(t, authClaims.CanDelete("documents")) // owner role on documents
	assert.True(t, authClaims.HasRole("admin"))
	assert.True(t, authClaims.IsAtLeast("member"))
	assert.WithinDuration(t, now.Add(time.Hour), authClaims.Expires(), time.Second)
	assert.WithinDuration(t, now, authClaims.IssuedAt(), time.Second)
}
