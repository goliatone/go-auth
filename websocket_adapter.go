package auth

import (
	"context"

	"github.com/goliatone/go-router"
)

// WSTokenValidator implements go-router's WSTokenValidator interface
// using the go-auth TokenService for seamless WebSocket authentication
type WSTokenValidator struct {
	tokenService TokenService
}

// NewWSTokenValidator creates a new WebSocket token validator using the provided TokenService
func NewWSTokenValidator(tokenService TokenService) *WSTokenValidator {
	return &WSTokenValidator{
		tokenService: tokenService,
	}
}

// Validate validates a token string and returns WebSocket-compatible auth claims
func (w *WSTokenValidator) Validate(tokenString string) (router.WSAuthClaims, error) {
	claims, err := w.tokenService.Validate(tokenString)
	if err != nil {
		return nil, err
	}
	return &WSAuthClaimsAdapter{claims: claims}, nil
}

// WSAuthClaimsAdapter adapts go-auth AuthClaims to go-router's WSAuthClaims interface
type WSAuthClaimsAdapter struct {
	claims AuthClaims
}

// Subject returns the subject claim
func (w *WSAuthClaimsAdapter) Subject() string {
	return w.claims.Subject()
}

// UserID returns the user ID
func (w *WSAuthClaimsAdapter) UserID() string {
	return w.claims.UserID()
}

// Role returns the user's role
func (w *WSAuthClaimsAdapter) Role() string {
	return w.claims.Role()
}

// CanRead checks if the user can read a specific resource
func (w *WSAuthClaimsAdapter) CanRead(resource string) bool {
	return w.claims.CanRead(resource)
}

// CanEdit checks if the user can edit a specific resource
func (w *WSAuthClaimsAdapter) CanEdit(resource string) bool {
	return w.claims.CanEdit(resource)
}

// CanCreate checks if the user can create a specific resource
func (w *WSAuthClaimsAdapter) CanCreate(resource string) bool {
	return w.claims.CanCreate(resource)
}

// CanDelete checks if the user can delete a specific resource
func (w *WSAuthClaimsAdapter) CanDelete(resource string) bool {
	return w.claims.CanDelete(resource)
}

// HasRole checks if the user has a specific role
func (w *WSAuthClaimsAdapter) HasRole(role string) bool {
	return w.claims.HasRole(role)
}

// IsAtLeast checks if the user's role is at least the minimum required role
func (w *WSAuthClaimsAdapter) IsAtLeast(minRole string) bool {
	return w.claims.IsAtLeast(minRole)
}

// NewWSAuthMiddleware creates a fully configured WebSocket authentication middleware
// using the go-auth TokenService. This is a convenience function for go-auth users.
func (a *Auther) NewWSAuthMiddleware(config ...router.WSAuthConfig) router.WebSocketMiddleware {
	validator := NewWSTokenValidator(a.tokenService)
	
	// Use provided config or create default
	var cfg router.WSAuthConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	
	// Always set our token validator
	cfg.TokenValidator = validator
	
	return router.NewWSAuth(cfg)
}

// WSAuthClaimsFromContext is a convenience function to retrieve auth claims from WebSocket context.
// It returns the underlying go-auth AuthClaims for easier access to go-auth specific functionality.
func WSAuthClaimsFromContext(ctx context.Context) (AuthClaims, bool) {
	wsAuthClaims, ok := router.WSAuthClaimsFromContext(ctx)
	if !ok {
		return nil, false
	}
	
	// If it's our adapter, return the underlying go-auth claims
	if adapter, ok := wsAuthClaims.(*WSAuthClaimsAdapter); ok {
		return adapter.claims, true
	}
	
	// Otherwise, return nil since it's not from go-auth
	return nil, false
}