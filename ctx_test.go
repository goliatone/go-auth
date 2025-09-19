package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/assert"
)

func TestGetClaims(t *testing.T) {
	tests := []struct {
		name       string
		setupCtx   func() context.Context
		wantClaims AuthClaims
		wantOK     bool
	}{
		{
			name: "should return claims when present in context",
			setupCtx: func() context.Context {
				claims := &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "user123",
					},
					UID:      "user123",
					UserRole: "admin",
				}
				ctx := context.Background()
				return WithClaimsContext(ctx, claims)
			},
			wantOK: true,
		},
		{
			name: "should return false when no claims in context",
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantClaims: nil,
			wantOK:     false,
		},
		{
			name: "should return false when context has wrong type",
			setupCtx: func() context.Context {
				ctx := context.Background()
				return context.WithValue(ctx, claimsCtxKey, "not-a-claims-object")
			},
			wantClaims: nil,
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			gotClaims, gotOK := GetClaims(ctx)

			assert.Equal(t, tt.wantOK, gotOK)
			if tt.wantOK {
				assert.NotNil(t, gotClaims)
				assert.Equal(t, "user123", gotClaims.Subject())
				assert.Equal(t, "user123", gotClaims.UserID())
				assert.Equal(t, "admin", gotClaims.Role())
			} else {
				assert.Nil(t, gotClaims)
			}
		})
	}
}

func TestCan(t *testing.T) {
	tests := []struct {
		name       string
		setupCtx   func() context.Context
		resource   string
		permission string
		want       bool
	}{
		{
			name: "should return true when admin can read",
			setupCtx: func() context.Context {
				claims := &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "user123",
					},
					UID:      "user123",
					UserRole: "admin",
				}
				ctx := context.Background()
				return WithClaimsContext(ctx, claims)
			},
			resource:   "project-123",
			permission: "read",
			want:       true,
		},
		{
			name: "should return true when admin can edit",
			setupCtx: func() context.Context {
				claims := &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "user123",
					},
					UID:      "user123",
					UserRole: "admin",
				}
				ctx := context.Background()
				return WithClaimsContext(ctx, claims)
			},
			resource:   "project-123",
			permission: "edit",
			want:       true,
		},
		{
			name: "should return true when admin can create",
			setupCtx: func() context.Context {
				claims := &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "user123",
					},
					UID:      "user123",
					UserRole: "admin",
				}
				ctx := context.Background()
				return WithClaimsContext(ctx, claims)
			},
			resource:   "project-123",
			permission: "create",
			want:       true,
		},
		{
			name: "should return false when admin cannot delete (only owner can)",
			setupCtx: func() context.Context {
				claims := &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "user123",
					},
					UID:      "user123",
					UserRole: "admin",
				}
				ctx := context.Background()
				return WithClaimsContext(ctx, claims)
			},
			resource:   "project-123",
			permission: "delete",
			want:       false,
		},
		{
			name: "should return true when owner can delete",
			setupCtx: func() context.Context {
				claims := &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "user123",
					},
					UID:      "user123",
					UserRole: "owner",
				}
				ctx := context.Background()
				return WithClaimsContext(ctx, claims)
			},
			resource:   "project-123",
			permission: "delete",
			want:       true,
		},
		{
			name: "should return false when guest cannot edit",
			setupCtx: func() context.Context {
				claims := &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "user123",
					},
					UID:      "user123",
					UserRole: "guest",
				}
				ctx := context.Background()
				return WithClaimsContext(ctx, claims)
			},
			resource:   "project-123",
			permission: "edit",
			want:       false,
		},
		{
			name: "should return true for resource-specific permissions",
			setupCtx: func() context.Context {
				claims := &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "user123",
					},
					UID:      "user123",
					UserRole: "guest", // Global role is guest
					Resources: map[string]string{
						"project-123": "admin", // But admin for this specific project
					},
				}
				ctx := context.Background()
				return WithClaimsContext(ctx, claims)
			},
			resource:   "project-123",
			permission: "create", // Guest can't create globally, but admin can
			want:       true,
		},
		{
			name: "should return false when no claims in context",
			setupCtx: func() context.Context {
				return context.Background()
			},
			resource:   "project-123",
			permission: "read",
			want:       false,
		},
		{
			name: "should return false for invalid permission",
			setupCtx: func() context.Context {
				claims := &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "user123",
					},
					UID:      "user123",
					UserRole: "admin",
				}
				ctx := context.Background()
				return WithClaimsContext(ctx, claims)
			},
			resource:   "project-123",
			permission: "invalid",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			got := Can(ctx, tt.resource, tt.permission)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetRouterClaims(t *testing.T) {
	tests := []struct {
		name    string
		setupFn func() router.Context
		key     string
		wantOK  bool
	}{
		{
			name: "should return claims when present with default key",
			setupFn: func() router.Context {
				ctx := router.NewMockContext()
				ctx.LocalsMock["user"] = &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "user123",
					},
					UID:      "user123",
					UserRole: "admin",
				}
				return ctx
			},
			key:    "", // Use default key
			wantOK: true,
		},
		{
			name: "should return claims when present with custom key",
			setupFn: func() router.Context {
				ctx := router.NewMockContext()
				ctx.LocalsMock["custom-claims"] = &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "user123",
					},
					UID:      "user123",
					UserRole: "admin",
				}
				return ctx
			},
			key:    "custom-claims",
			wantOK: true,
		},
		{
			name: "should return false when key not present",
			setupFn: func() router.Context {
				ctx := router.NewMockContext()
				return ctx
			},
			key:    "user",
			wantOK: false,
		},
		{
			name: "should return false when value is wrong type",
			setupFn: func() router.Context {
				ctx := router.NewMockContext()
				ctx.LocalsMock["user"] = "not-a-claims-object"
				return ctx
			},
			key:    "user",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupFn()
			gotClaims, gotOK := GetRouterClaims(ctx, tt.key)

			assert.Equal(t, tt.wantOK, gotOK)
			if tt.wantOK {
				assert.NotNil(t, gotClaims)
				assert.Equal(t, "user123", gotClaims.Subject())
				assert.Equal(t, "user123", gotClaims.UserID())
				assert.Equal(t, "admin", gotClaims.Role())
			} else {
				assert.Nil(t, gotClaims)
			}
		})
	}
}

func TestCanFromRouter(t *testing.T) {
	tests := []struct {
		name       string
		setupFn    func() router.Context
		resource   string
		permission string
		want       bool
	}{
		{
			name: "should return true when admin can read",
			setupFn: func() router.Context {
				ctx := router.NewMockContext()
				ctx.LocalsMock["user"] = &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "user123",
					},
					UID:      "user123",
					UserRole: "admin",
				}
				return ctx
			},
			resource:   "project-123",
			permission: "read",
			want:       true,
		},
		{
			name: "should return false when guest cannot create",
			setupFn: func() router.Context {
				ctx := router.NewMockContext()
				ctx.LocalsMock["user"] = &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "user123",
					},
					UID:      "user123",
					UserRole: "guest",
				}
				return ctx
			},
			resource:   "project-123",
			permission: "create",
			want:       false,
		},
		{
			name: "should return false when no claims in context",
			setupFn: func() router.Context {
				ctx := router.NewMockContext()
				return ctx
			},
			resource:   "project-123",
			permission: "read",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupFn()
			got := CanFromRouter(ctx, tt.resource, tt.permission)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWithClaimsContext(t *testing.T) {
	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		UID:      "user123",
		UserRole: "admin",
		Resources: map[string]string{
			"project-1": "owner",
			"project-2": "member",
		},
	}

	ctx := context.Background()
	newCtx := WithClaimsContext(ctx, claims)

	retrievedClaims, ok := GetClaims(newCtx)
	assert.True(t, ok)
	assert.NotNil(t, retrievedClaims)
	assert.Equal(t, "user123", retrievedClaims.Subject())
	assert.Equal(t, "user123", retrievedClaims.UserID())
	assert.Equal(t, "admin", retrievedClaims.Role())
	assert.True(t, retrievedClaims.CanCreate("project-1"))  // owner can create
	assert.True(t, retrievedClaims.CanEdit("project-2"))    // member can edit
	assert.False(t, retrievedClaims.CanDelete("project-2")) // member cannot delete
}

//--------------------------------------------------------------------------------------
// Integration Tests for GetClaims and Can Functions
//--------------------------------------------------------------------------------------

func TestGetClaimsIntegration_EndToEnd(t *testing.T) {
	t.Run("integration test - GetClaims and Can work end-to-end", func(t *testing.T) {
		// Create mock claims with comprehensive data
		mockClaims := &JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "integration-user-123",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "test-issuer",
				Audience:  []string{"test-audience"},
			},
			UID:      "integration-user-123",
			UserRole: "admin",
			Resources: map[string]string{
				"project-alpha": "owner",
				"project-beta":  "member",
				"project-gamma": "guest",
			},
		}

		// Create a standard context.Context and enrich it with claims
		ctx := context.Background()
		enrichedCtx := WithClaimsContext(ctx, mockClaims)

		// Test GetClaims functionality
		retrievedClaims, ok := GetClaims(enrichedCtx)
		assert.True(t, ok, "GetClaims should successfully retrieve claims from enriched context")
		assert.NotNil(t, retrievedClaims, "Retrieved claims should not be nil")

		// Validate basic claim properties
		assert.Equal(t, "integration-user-123", retrievedClaims.Subject(), "Subject should match")
		assert.Equal(t, "integration-user-123", retrievedClaims.UserID(), "UserID should match")
		assert.Equal(t, "admin", retrievedClaims.Role(), "Role should match")

		// Test Can functionality with global role permissions
		t.Run("global role permissions", func(t *testing.T) {
			// Admin role can read, edit, create but not delete (only owner can)
			assert.True(t, Can(enrichedCtx, "any-resource", "read"), "Admin should be able to read any resource")
			assert.True(t, Can(enrichedCtx, "any-resource", "edit"), "Admin should be able to edit any resource")
			assert.True(t, Can(enrichedCtx, "any-resource", "create"), "Admin should be able to create any resource")
			assert.False(t, Can(enrichedCtx, "any-resource", "delete"), "Admin should not be able to delete (only owner can)")
		})

		// Test Can functionality with resource-specific permissions
		t.Run("resource-specific permissions", func(t *testing.T) {
			// project-alpha: user is owner (can do everything)
			assert.True(t, Can(enrichedCtx, "project-alpha", "read"), "Owner should be able to read project-alpha")
			assert.True(t, Can(enrichedCtx, "project-alpha", "edit"), "Owner should be able to edit project-alpha")
			assert.True(t, Can(enrichedCtx, "project-alpha", "create"), "Owner should be able to create in project-alpha")
			assert.True(t, Can(enrichedCtx, "project-alpha", "delete"), "Owner should be able to delete in project-alpha")

			// project-beta: user is member (can read and edit, but not create or delete)
			assert.True(t, Can(enrichedCtx, "project-beta", "read"), "Member should be able to read project-beta")
			assert.True(t, Can(enrichedCtx, "project-beta", "edit"), "Member should be able to edit project-beta")
			assert.False(t, Can(enrichedCtx, "project-beta", "create"), "Member should not be able to create in project-beta")
			assert.False(t, Can(enrichedCtx, "project-beta", "delete"), "Member should not be able to delete in project-beta")

			// project-gamma: user is guest (can only read)
			assert.True(t, Can(enrichedCtx, "project-gamma", "read"), "Guest should be able to read project-gamma")
			assert.False(t, Can(enrichedCtx, "project-gamma", "edit"), "Guest should not be able to edit project-gamma")
			assert.False(t, Can(enrichedCtx, "project-gamma", "create"), "Guest should not be able to create in project-gamma")
			assert.False(t, Can(enrichedCtx, "project-gamma", "delete"), "Guest should not be able to delete in project-gamma")
		})

		// Test invalid permissions
		t.Run("invalid permissions", func(t *testing.T) {
			assert.False(t, Can(enrichedCtx, "any-resource", "invalid"), "Invalid permission should return false")
			assert.False(t, Can(enrichedCtx, "any-resource", ""), "Empty permission should return false")
		})

		// Test error cases
		t.Run("error cases", func(t *testing.T) {
			// Test with empty context (no claims)
			emptyCtx := context.Background()
			emptyClaims, ok := GetClaims(emptyCtx)
			assert.False(t, ok, "GetClaims should return false for empty context")
			assert.Nil(t, emptyClaims, "Claims should be nil for empty context")
			assert.False(t, Can(emptyCtx, "any-resource", "read"), "Can should return false for empty context")

			// Test with context containing wrong type
			wrongTypeCtx := context.WithValue(context.Background(), claimsCtxKey, "not-claims")
			wrongTypeClaims, ok := GetClaims(wrongTypeCtx)
			assert.False(t, ok, "GetClaims should return false for wrong type in context")
			assert.Nil(t, wrongTypeClaims, "Claims should be nil for wrong type in context")
			assert.False(t, Can(wrongTypeCtx, "any-resource", "read"), "Can should return false for wrong type in context")
		})
	})

	t.Run("integration test - role hierarchy validation", func(t *testing.T) {
		testRoles := []struct {
			role                 string
			canRead, canEdit     bool
			canCreate, canDelete bool
		}{
			{"guest", true, false, false, false},
			{"member", true, true, false, false},
			{"admin", true, true, true, false},
			{"owner", true, true, true, true},
		}

		for _, testRole := range testRoles {
			t.Run(testRole.role, func(t *testing.T) {
				claims := &JWTClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "test-user",
					},
					UID:      "test-user",
					UserRole: testRole.role,
				}

				ctx := WithClaimsContext(context.Background(), claims)

				assert.Equal(t, testRole.canRead, Can(ctx, "test-resource", "read"), "Read permission mismatch for %s", testRole.role)
				assert.Equal(t, testRole.canEdit, Can(ctx, "test-resource", "edit"), "Edit permission mismatch for %s", testRole.role)
				assert.Equal(t, testRole.canCreate, Can(ctx, "test-resource", "create"), "Create permission mismatch for %s", testRole.role)
				assert.Equal(t, testRole.canDelete, Can(ctx, "test-resource", "delete"), "Delete permission mismatch for %s", testRole.role)
			})
		}
	})

	t.Run("integration test - context propagation patterns", func(t *testing.T) {
		// Simulate how the middleware would propagate context
		originalClaims := &JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "middleware-user",
			},
			UID:      "middleware-user",
			UserRole: "admin",
			Resources: map[string]string{
				"api-resource": "owner",
			},
		}

		// Step 1: Start with background context (simulating HTTP request start)
		requestCtx := context.Background()

		// Step 2: Middleware adds claims to context (simulating our ContextEnricher)
		middlewareCtx := WithClaimsContext(requestCtx, originalClaims)

		// Step 3: Handler function receives enriched context and can use helper functions
		handlerFunction := func(ctx context.Context) (bool, bool, bool) {
			// This simulates what a handler would do
			claims, hasClaimsOK := GetClaims(ctx)
			canReadOK := Can(ctx, "api-resource", "read")
			canDeleteOK := Can(ctx, "api-resource", "delete")

			// Validate claims are correctly retrieved
			if hasClaimsOK {
				assert.Equal(t, "middleware-user", claims.Subject())
				assert.Equal(t, "admin", claims.Role())
			}

			return hasClaimsOK, canReadOK, canDeleteOK
		}

		// Execute the simulated handler
		hasClaimsOK, canReadOK, canDeleteOK := handlerFunction(middlewareCtx)

		// Validate end-to-end functionality
		assert.True(t, hasClaimsOK, "Handler should be able to retrieve claims from context")
		assert.True(t, canReadOK, "Handler should be able to check read permissions")
		assert.True(t, canDeleteOK, "Handler should be able to check delete permissions (owner role for resource)")

		// Validate that original context doesn't have claims
		hasOriginalClaims, originalCanRead, _ := handlerFunction(requestCtx)
		assert.False(t, hasOriginalClaims, "Original context should not have claims")
		assert.False(t, originalCanRead, "Original context should not allow permissions")
	})
}
