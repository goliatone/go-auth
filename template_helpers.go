package auth

import (
	"maps"

	"github.com/goliatone/go-auth/middleware/csrf"
	"github.com/goliatone/go-router"
)

var TemplateUserKey = "current_user"

// TemplateHelpers returns a map of helper functions and data that can be used
// with go-template's WithGlobalData option for authentication-related template functionality.
//
// Usage:
//
//	renderer, err := template.NewRenderer(
//	    template.WithBaseDir("./templates"),
//	    template.WithGlobalData(auth.TemplateHelpers()),
//	)
//
// In templates, you can then use:
//
//	{% if current_user %}
//	{% if current_user|has_role:"admin" %}
//	{% if current_user|can_create:"posts" %}
//	{{ csrf_field }}
//	{{ csrf_token }}
func TemplateHelpers() map[string]any {
	helpers := map[string]any{
		// Authentication helper functions
		"is_authenticated": isAuthenticated,
		"has_role":         hasRole,
		"is_at_least":      isAtLeast,
		"can_read":         canRead,
		"can_edit":         canEdit,
		"can_create":       canCreate,
		"can_delete":       canDelete,
		"can_access":       canAccess,

		// Role constants for easy template access
		"roles": map[string]string{
			"guest":  string(RoleGuest),
			"member": string(RoleMember),
			"admin":  string(RoleAdmin),
			"owner":  string(RoleOwner),
		},
	}

	// add CSRF template helpers
	maps.Copy(helpers, csrf.CSRFTemplateHelpers())

	return helpers
}

// TemplateHelpersWithUser returns template helpers with a specific user set as current_user.
// This is useful when you want to inject the current user directly into the global context.
//
// Usage:
//
//	currentUser := getCurrentUser(ctx)
//	renderer, err := template.NewRenderer(
//	    template.WithBaseDir("./templates"),
//	    template.WithGlobalData(auth.TemplateHelpersWithUser(currentUser)),
//	)
func TemplateHelpersWithUser(user *User) map[string]any {
	helpers := TemplateHelpers()
	helpers[TemplateUserKey] = user
	return helpers
}

// TemplateHelpersWithRouter returns template helpers with user data extracted from router context.
// This is useful for automatically injecting the current user from JWT middleware context.
// It also includes CSRF token helpers when a CSRF token is available in the context.
//
// Usage:
//
//	// In your route handler
//	globalData := auth.TemplateHelpersWithRouter(ctx, auth.TemplateUserKey)
//	// Merge with request-specific data and render template
//
// Or with a reusable render helper:
//
//	func renderTemplate(ctx router.Context, name string, data map[string]any) (string, error) {
//		globalData := auth.TemplateHelpersWithRouter(ctx, auth.TemplateUserKey)
//		// Create renderer with current context or use a cached one
//		return renderer.RenderTemplate(name, data)
//	}
func TemplateHelpersWithRouter(ctx router.Context, userKey string) map[string]any {
	if userKey == "" {
		userKey = TemplateUserKey
	}

	helpers := TemplateHelpers()

	// Try to get user from router context
	if user := ctx.Locals(userKey); user != nil {
		helpers[TemplateUserKey] = user
	}

	// Merge CSRF helpers with router context for actual token values
	for key, value := range csrf.CSRFTemplateHelpersWithRouter(ctx, csrf.DefaultContextKey) {
		helpers[key] = value
	}

	return helpers
}

// GetTemplateUser is a convenience function to extract user data from router context
// for template usage. It returns the user object and a boolean indicating if it was found.
//
// Usage:
//
//	if user, ok := auth.GetTemplateUser(ctx, auth.TemplateUserKey); ok {
//		// Use user in template data
//		data["user"] = user
//	}
func GetTemplateUser(ctx router.Context, userKey string) (any, bool) {
	if userKey == "" {
		userKey = TemplateUserKey
	}

	user := ctx.Locals(userKey)
	return user, user != nil
}

// isAuthenticated checks if the provided user object is not nil
func isAuthenticated(user any) bool {
	if user == nil {
		return false
	}

	switch u := user.(type) {
	case *User:
		return u != nil
	case User:
		return true
	case AuthClaims:
		return u != nil && u.UserID() != ""
	case map[string]any:
		// Handle JSON-converted user objects
		return len(u) > 0
	default:
		return false
	}
}

// hasRole checks if the user has the specified role
func hasRole(user any, role string) bool {
	targetRole := UserRole(role)

	switch u := user.(type) {
	case *User:
		if u == nil {
			return false
		}
		return u.Role == targetRole
	case User:
		return u.Role == targetRole
	case AuthClaims:
		if u == nil {
			return false
		}
		return u.HasRole(role)
	case map[string]any:
		// Handle JSON-converted user objects
		if userRole, exists := u["user_role"]; exists {
			if roleStr, ok := userRole.(string); ok {
				return UserRole(roleStr) == targetRole
			}
		}
		return false
	default:
		return false
	}
}

// isAtLeast checks if the user's role is at least the minimum required level
func isAtLeast(user any, minRole string) bool {
	minRoleTyped := UserRole(minRole)

	switch u := user.(type) {
	case *User:
		if u == nil {
			return false
		}
		return u.Role.IsAtLeast(minRoleTyped)
	case User:
		return u.Role.IsAtLeast(minRoleTyped)
	case AuthClaims:
		if u == nil {
			return false
		}
		return u.IsAtLeast(minRole)
	case map[string]any:
		// Handle JSON-converted user objects
		if userRole, exists := u["user_role"]; exists {
			if roleStr, ok := userRole.(string); ok {
				return UserRole(roleStr).IsAtLeast(minRoleTyped)
			}
		}
		return false
	default:
		return false
	}
}

// canRead checks if the user can read resources
func canRead(user any) bool {
	switch u := user.(type) {
	case *User:
		if u == nil {
			return false
		}
		return u.Role.CanRead()
	case User:
		return u.Role.CanRead()
	case AuthClaims:
		if u == nil {
			return false
		}
		return u.CanRead("*")
	case map[string]any:
		// Handle JSON-converted user objects
		if userRole, exists := u["user_role"]; exists {
			if roleStr, ok := userRole.(string); ok {
				return UserRole(roleStr).CanRead()
			}
		}
		return false
	default:
		return false
	}
}

// canEdit checks if the user can edit resources
func canEdit(user any) bool {
	switch u := user.(type) {
	case *User:
		if u == nil {
			return false
		}
		return u.Role.CanEdit()
	case User:
		return u.Role.CanEdit()
	case AuthClaims:
		if u == nil {
			return false
		}
		return u.CanEdit("*")
	case map[string]any:
		// Handle JSON-converted user objects
		if userRole, exists := u["user_role"]; exists {
			if roleStr, ok := userRole.(string); ok {
				return UserRole(roleStr).CanEdit()
			}
		}
		return false
	default:
		return false
	}
}

// canCreate checks if the user can create resources
func canCreate(user any) bool {
	switch u := user.(type) {
	case *User:
		if u == nil {
			return false
		}
		return u.Role.CanCreate()
	case User:
		return u.Role.CanCreate()
	case AuthClaims:
		if u == nil {
			return false
		}
		return u.CanCreate("*")
	case map[string]any:
		// Handle JSON-converted user objects
		if userRole, exists := u["user_role"]; exists {
			if roleStr, ok := userRole.(string); ok {
				return UserRole(roleStr).CanCreate()
			}
		}
		return false
	default:
		return false
	}
}

// canDelete checks if the user can delete resources
func canDelete(user any) bool {
	switch u := user.(type) {
	case *User:
		if u == nil {
			return false
		}
		return u.Role.CanDelete()
	case User:
		return u.Role.CanDelete()
	case AuthClaims:
		if u == nil {
			return false
		}
		return u.CanDelete("*")
	case map[string]any:
		// Handle JSON-converted user objects
		if userRole, exists := u["user_role"]; exists {
			if roleStr, ok := userRole.(string); ok {
				return UserRole(roleStr).CanDelete()
			}
		}
		return false
	default:
		return false
	}
}

// canAccess is a convenience function that checks if a user can perform a specific action
// Actions supported: "read", "edit", "create", "delete"
func canAccess(user any, action string) bool {
	switch action {
	case "read":
		return canRead(user)
	case "edit":
		return canEdit(user)
	case "create":
		return canCreate(user)
	case "delete":
		return canDelete(user)
	default:
		return false
	}
}
