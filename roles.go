package auth

// RoleValidator defines the interface for role-based access control validation
type RoleValidator interface {
	// CanRead checks if the role can read a specific resource
	CanRead(resource string) bool

	// CanEdit checks if the role can edit a specific resource
	CanEdit(resource string) bool

	// CanCreate checks if the role can create a specific resource
	CanCreate(resource string) bool

	// CanDelete checks if the role can delete a specific resource
	CanDelete(resource string) bool

	// HasRole checks if the user has a specific role
	HasRole(role string) bool

	// IsAtLeast checks if the user's role is at least the minimum required role
	IsAtLeast(minRole UserRole) bool
}

// IsValid checks if the role is one of the predefined valid roles
func (r UserRole) IsValid() bool {
	switch r {
	case RoleGuest, RoleMember, RoleAdmin, RoleOwner:
		return true
	default:
		return false
	}
}

// CanRead checks if this role can read resources
func (r UserRole) CanRead() bool {
	switch r {
	case RoleGuest, RoleMember, RoleAdmin, RoleOwner:
		return true
	default:
		return false
	}
}

// CanEdit checks if this role can edit resources
func (r UserRole) CanEdit() bool {
	switch r {
	case RoleMember, RoleAdmin, RoleOwner:
		return true
	default:
		return false
	}
}

// CanCreate checks if this role can create resources
func (r UserRole) CanCreate() bool {
	switch r {
	case RoleAdmin, RoleOwner:
		return true
	default:
		return false
	}
}

// CanDelete checks if this role can delete resources
func (r UserRole) CanDelete() bool {
	switch r {
	case RoleOwner:
		return true
	default:
		return false
	}
}

// IsAtLeast checks if this role meets the minimum required level
func (r UserRole) IsAtLeast(minRole UserRole) bool {
	roleHierarchy := map[UserRole]int{
		RoleGuest:  0,
		RoleMember: 1,
		RoleAdmin:  2,
		RoleOwner:  3,
	}

	currentLevel, exists := roleHierarchy[r]
	if !exists {
		return false
	}

	minLevel, exists := roleHierarchy[minRole]
	if !exists {
		return false
	}

	return currentLevel >= minLevel
}

// GetAllRoles returns all predefined roles in hierarchical order
func GetAllRoles() []UserRole {
	return []UserRole{
		RoleGuest,
		RoleMember,
		RoleAdmin,
		RoleOwner,
	}
}

// ParseRole safely parses a string into a UserRole type
func ParseRole(roleStr string) (UserRole, bool) {
	role := UserRole(roleStr)
	return role, role.IsValid()
}
