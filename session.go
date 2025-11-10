package auth

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

var _ Session = &SessionObject{}
var _ RoleCapableSession = &SessionObject{}

type SessionObject struct {
	UserID         string         `json:"user_id,omitempty"`
	Audience       []string       `json:"audience,omitempty"`
	Issuer         string         `json:"issuer,omitempty"`
	IssuedAt       *time.Time     `json:"issued_at,omitempty"`
	ExpirationDate *time.Time     `json:"expiration_date,omitempty"`
	Data           map[string]any `json:"data,omitempty"`
}

func (s *SessionObject) GetUserID() string {
	return s.UserID
}

func (s *SessionObject) GetUserUUID() (uuid.UUID, error) {
	return uuid.Parse(s.UserID)
}

func (s *SessionObject) GetAudience() []string {
	return s.Audience
}

func (s *SessionObject) GetIssuer() string {
	return s.Issuer
}

func (s *SessionObject) GetIssuedAt() *time.Time {
	return s.IssuedAt
}

func (s *SessionObject) GetData() map[string]any {
	return s.Data
}

// RoleCapableSession implementation methods

// CanRead checks if the role can read a specific resource
func (s *SessionObject) CanRead(resource string) bool {
	// Try to get resource-specific permissions first
	if s.Data != nil {
		if resourceRoles, exists := s.Data["resources"]; exists {
			if roleMap, ok := resourceRoles.(map[string]any); ok {
				if roleStr, hasRole := roleMap[resource]; hasRole {
					if role, ok := roleStr.(string); ok {
						userRole := UserRole(role)
						return userRole.CanRead()
					}
				}
			}
		}
	}

	// Use global role from session data
	return s.getGlobalRole().CanRead()
}

// CanEdit checks if the role can edit a specific resource
func (s *SessionObject) CanEdit(resource string) bool {
	// Try to get resource-specific permissions first
	if s.Data != nil {
		if resourceRoles, exists := s.Data["resources"]; exists {
			if roleMap, ok := resourceRoles.(map[string]any); ok {
				if roleStr, hasRole := roleMap[resource]; hasRole {
					if role, ok := roleStr.(string); ok {
						userRole := UserRole(role)
						return userRole.CanEdit()
					}
				}
			}
		}
	}

	// Use global role from session data
	return s.getGlobalRole().CanEdit()
}

// CanCreate checks if the role can create a specific resource
func (s *SessionObject) CanCreate(resource string) bool {
	// Try to get resource-specific permissions first
	if s.Data != nil {
		if resourceRoles, exists := s.Data["resources"]; exists {
			if roleMap, ok := resourceRoles.(map[string]any); ok {
				if roleStr, hasRole := roleMap[resource]; hasRole {
					if role, ok := roleStr.(string); ok {
						userRole := UserRole(role)
						return userRole.CanCreate()
					}
				}
			}
		}
	}

	// Use global role from session data
	return s.getGlobalRole().CanCreate()
}

// CanDelete checks if the role can delete a specific resource
func (s *SessionObject) CanDelete(resource string) bool {
	// Try to get resource-specific permissions first
	if s.Data != nil {
		if resourceRoles, exists := s.Data["resources"]; exists {
			if roleMap, ok := resourceRoles.(map[string]any); ok {
				if roleStr, hasRole := roleMap[resource]; hasRole {
					if role, ok := roleStr.(string); ok {
						userRole := UserRole(role)
						return userRole.CanDelete()
					}
				}
			}
		}
	}

	// Use global role from session data
	return s.getGlobalRole().CanDelete()
}

// HasRole checks if the user has a specific role
func (s *SessionObject) HasRole(role string) bool {
	globalRole := s.getGlobalRole()
	return string(globalRole) == role
}

// IsAtLeast checks if the user's role is at least the minimum required role
func (s *SessionObject) IsAtLeast(minRole UserRole) bool {
	globalRole := s.getGlobalRole()
	return globalRole.IsAtLeast(minRole)
}

// getGlobalRole retrieves the global role from session data with fallback to guest
func (s *SessionObject) getGlobalRole() UserRole {
	if s.Data != nil {
		if roleData, exists := s.Data["role"]; exists {
			if roleStr, ok := roleData.(string); ok {
				if role, valid := ParseRole(roleStr); valid {
					return role
				}
			}
		}
	}
	// Default to guest role if no role is found or parsing fails
	return RoleGuest
}

// TODO: enable only in development!
func (s SessionObject) String() string {
	return fmt.Sprintf(
		"user=%s aud=%v iss=%s iat=%s data=%v",
		s.UserID,
		s.Audience,
		s.Issuer,
		s.IssuedAt.Format(time.RFC1123),
		s.Data,
	)
}

// sessionFromAuthClaims creates a SessionObject from modern AuthClaims interface
func sessionFromAuthClaims(claims AuthClaims) (*SessionObject, error) {
	if claims == nil {
		return nil, ErrUnableToParseData
	}

	// Build the data map from the claims
	data := make(map[string]any)
	data["role"] = claims.Role()

	// Add resource roles if available (for JWTClaims implementation)
	if jwtClaims, ok := claims.(*JWTClaims); ok {
		if len(jwtClaims.Resources) > 0 {
			data["resources"] = jwtClaims.Resources
		}

		if len(jwtClaims.Metadata) > 0 {
			data["metadata"] = jwtClaims.Metadata
		}
	}

	// Convert audience from jwt.ClaimStrings to []string
	var audience []string
	if jwtClaims, ok := claims.(*JWTClaims); ok {
		if jwtClaims.RegisteredClaims.Audience != nil {
			for _, aud := range jwtClaims.RegisteredClaims.Audience {
				audience = append(audience, aud)
			}
		}
	}

	issuedAt := claims.IssuedAt()
	expiresAt := claims.Expires()

	return &SessionObject{
		UserID:         claims.UserID(),
		Audience:       audience,
		Issuer:         getIssuerFromClaims(claims),
		Data:           data,
		IssuedAt:       &issuedAt,
		ExpirationDate: &expiresAt,
	}, nil
}

// getIssuerFromClaims extracts the issuer from AuthClaims
func getIssuerFromClaims(claims AuthClaims) string {
	if jwtClaims, ok := claims.(*JWTClaims); ok {
		if jwtClaims.RegisteredClaims.Issuer != "" {
			return jwtClaims.RegisteredClaims.Issuer
		}
	}
	// Fallback to subject if no issuer is available
	return claims.Subject()
}
