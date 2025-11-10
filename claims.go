package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthClaims represents structured JWT claims with enhanced permission checking
type AuthClaims interface {
	Subject() string
	UserID() string
	Role() string
	CanRead(resource string) bool
	CanEdit(resource string) bool
	CanCreate(resource string) bool
	CanDelete(resource string) bool
	HasRole(role string) bool
	IsAtLeast(minRole string) bool
	Expires() time.Time
	IssuedAt() time.Time
}

// JWTClaims is the concrete implementation of AuthClaims
type JWTClaims struct {
	jwt.RegisteredClaims
	UID       string            `json:"uid,omitempty"`
	UserRole  string            `json:"role,omitempty"`
	Resources map[string]string `json:"res,omitempty"`      // resource -> role mapping
	Metadata  map[string]any    `json:"metadata,omitempty"` // extension payload
}

// Verify interface compliance
var _ AuthClaims = (*JWTClaims)(nil)

// Subject returns the subject claim
func (c *JWTClaims) Subject() string {
	return c.RegisteredClaims.Subject
}

// UserID returns the user ID
func (c *JWTClaims) UserID() string {
	if c.UID != "" {
		return c.UID
	}
	return c.Subject()
}

// Role returns the global role
func (c *JWTClaims) Role() string {
	return c.UserRole
}

// CanRead checks if the user can read a specific resource
func (c *JWTClaims) CanRead(resource string) bool {
	if resourceRole, exists := c.Resources[resource]; exists {
		return UserRole(resourceRole).CanRead()
	}
	return UserRole(c.UserRole).CanRead()
}

// CanEdit checks if the user can edit a specific resource
func (c *JWTClaims) CanEdit(resource string) bool {
	if resourceRole, exists := c.Resources[resource]; exists {
		return UserRole(resourceRole).CanEdit()
	}
	return UserRole(c.UserRole).CanEdit()
}

// CanCreate checks if the user can create a specific resource
func (c *JWTClaims) CanCreate(resource string) bool {
	if resourceRole, exists := c.Resources[resource]; exists {
		return UserRole(resourceRole).CanCreate()
	}
	return UserRole(c.UserRole).CanCreate()
}

// CanDelete checks if the user can delete a specific resource
func (c *JWTClaims) CanDelete(resource string) bool {
	if resourceRole, exists := c.Resources[resource]; exists {
		return UserRole(resourceRole).CanDelete()
	}
	return UserRole(c.UserRole).CanDelete()
}

// ResourceRoles exposes resource-specific roles for optional context enrichment.
func (c *JWTClaims) ResourceRoles() map[string]string {
	return c.Resources
}

// ClaimsMetadata exposes metadata extensions for optional context enrichment.
func (c *JWTClaims) ClaimsMetadata() map[string]any {
	return c.Metadata
}

// HasRole checks if the user has a specific role (either global or for any resource)
func (c *JWTClaims) HasRole(role string) bool {
	if c.UserRole == role {
		return true
	}
	for _, resourceRole := range c.Resources {
		if resourceRole == role {
			return true
		}
	}
	return false
}

// IsAtLeast checks if the user's role is at least the minimum required role
func (c *JWTClaims) IsAtLeast(minRole string) bool {
	return UserRole(c.UserRole).IsAtLeast(UserRole(minRole))
}

// Expires returns the expiration time
func (c *JWTClaims) Expires() time.Time {
	if c.RegisteredClaims.ExpiresAt != nil {
		return c.RegisteredClaims.ExpiresAt.Time
	}
	return time.Time{}
}

// IssuedAt returns the issued at time
func (c *JWTClaims) IssuedAt() time.Time {
	if c.RegisteredClaims.IssuedAt != nil {
		return c.RegisteredClaims.IssuedAt.Time
	}
	return time.Time{}
}
