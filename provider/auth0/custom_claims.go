package auth0

import (
	"context"
	"encoding/json"
)

// Auth0CustomClaims holds custom claims from Auth0 tokens.
type Auth0CustomClaims struct {
	Scope          string            `json:"scope"`
	Permissions    []string          `json:"permissions"`
	Email          string            `json:"email"`
	EmailVerified  bool              `json:"email_verified"`
	Name           string            `json:"name"`
	Nickname       string            `json:"nickname"`
	Picture        string            `json:"picture"`
	Metadata       map[string]any    `json:"app_metadata"`
	OrganizationID string            `json:"org_id"`
	TenantID       string            `json:"tenant_id"`
	ResourceRoles  map[string]string `json:"resource_roles"`
	Raw            map[string]any    `json:"-"`
}

// Validate satisfies validator.CustomClaims.
func (c *Auth0CustomClaims) Validate(ctx context.Context) error {
	return nil
}

// UnmarshalJSON captures both known and raw claims for custom mapping.
func (c *Auth0CustomClaims) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	type alias Auth0CustomClaims
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*c = Auth0CustomClaims(decoded)
	c.Raw = raw
	return nil
}
