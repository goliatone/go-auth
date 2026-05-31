package oidc

import (
	"context"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
)

type DefaultClaimsMapper struct{}

func (DefaultClaimsMapper) MapClaims(_ context.Context, provider ProviderConfig, claims jwt.MapClaims, userInfo map[string]any) (ExternalIdentity, *auth.JWTClaims, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return ExternalIdentity{}, nil, auth.ErrUnableToMapClaims
	}

	email := stringClaim(claims, userInfo, "email")
	emailVerified := boolClaim(claims, userInfo, "email_verified")
	identity := ExternalIdentity{
		Provider:      provider.Key,
		Subject:       sub,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          stringClaim(claims, userInfo, "name"),
		GivenName:     stringClaim(claims, userInfo, "given_name"),
		FamilyName:    stringClaim(claims, userInfo, "family_name"),
		Nickname:      stringClaim(claims, userInfo, "nickname"),
		Picture:       stringClaim(claims, userInfo, "picture"),
		TenantID:      firstStringClaim(claims, userInfo, claimKeys(provider.ClaimKeys.TenantID, "tenant_id")),
		OrganizationID: firstStringClaim(claims, userInfo,
			claimKeys(provider.ClaimKeys.OrganizationID, "organization_id", "org_id"),
		),
		Roles:         sliceClaim(claims, userInfo, claimKeys(provider.ClaimKeys.Roles, "roles", "role")),
		Permissions:   sliceClaim(claims, userInfo, claimKeys(provider.ClaimKeys.Permissions, "permissions", "scope")),
		ResourceRoles: mapStringClaim(claims, userInfo, claimKeys(provider.ClaimKeys.ResourceRoles, "resource_roles")),
		Metadata:      map[string]any{"provider": provider.Key},
	}
	groups := sliceClaim(claims, userInfo, claimKeys(provider.ClaimKeys.Groups, "groups"))
	if len(groups) > 0 {
		identity.Metadata["groups"] = groups
	}

	authClaims := mapTokenClaimsToAuth(claims)
	if authClaims.Metadata == nil {
		authClaims.Metadata = map[string]any{}
	}
	if len(identity.ResourceRoles) > 0 {
		authClaims.Resources = identity.ResourceRoles
	}
	if len(identity.Roles) > 0 {
		authClaims.Metadata["roles"] = identity.Roles
	}
	if len(identity.Permissions) > 0 {
		authClaims.Metadata["permissions"] = identity.Permissions
	}
	if len(groups) > 0 {
		authClaims.Metadata["groups"] = groups
	}
	if identity.TenantID != "" {
		authClaims.Metadata["tenant_id"] = identity.TenantID
	}
	if identity.OrganizationID != "" {
		authClaims.Metadata["organization_id"] = identity.OrganizationID
	}
	authClaims.Metadata["provider"] = provider.Key
	authClaims.Metadata["provider_subject"] = sub
	if email != "" {
		authClaims.Metadata["email"] = email
	}
	if emailVerified {
		authClaims.Metadata["email_verified"] = true
	}

	return identity, authClaims, nil
}

func stringClaim(claims jwt.MapClaims, userInfo map[string]any, key string) string {
	if val, _ := userInfo[key].(string); val != "" {
		return val
	}
	val, _ := claims[key].(string)
	return val
}

func boolClaim(claims jwt.MapClaims, userInfo map[string]any, key string) bool {
	if val, ok := userInfo[key].(bool); ok {
		return val
	}
	val, _ := claims[key].(bool)
	return val
}

func claimKeys(configured []string, defaults ...string) []string {
	if len(configured) > 0 {
		return configured
	}
	return defaults
}

func firstStringClaim(claims jwt.MapClaims, userInfo map[string]any, keys []string) string {
	for _, key := range keys {
		if val := stringClaim(claims, userInfo, key); val != "" {
			return val
		}
	}
	return ""
}

func sliceClaim(claims jwt.MapClaims, userInfo map[string]any, keys []string) []string {
	for _, key := range keys {
		raw, ok := userInfo[key]
		if !ok {
			raw, ok = claims[key]
		}
		if !ok {
			continue
		}
		values := normalizeStringSlice(raw)
		if len(values) > 0 {
			return values
		}
	}
	return nil
}

func normalizeStringSlice(raw any) []string {
	switch val := raw.(type) {
	case string:
		return strings.Fields(val)
	case []string:
		return append([]string(nil), val...)
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

func mapStringClaim(claims jwt.MapClaims, userInfo map[string]any, keys []string) map[string]string {
	for _, key := range keys {
		raw, ok := userInfo[key]
		if !ok {
			raw, ok = claims[key]
		}
		if !ok {
			continue
		}
		values := normalizeStringMap(raw)
		if len(values) > 0 {
			return values
		}
	}
	return nil
}

func normalizeStringMap(raw any) map[string]string {
	switch val := raw.(type) {
	case map[string]string:
		out := make(map[string]string, len(val))
		for k, v := range val {
			if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
				out[k] = v
			}
		}
		return out
	case map[string]any:
		out := make(map[string]string, len(val))
		for k, v := range val {
			if s, ok := v.(string); ok && strings.TrimSpace(k) != "" && strings.TrimSpace(s) != "" {
				out[k] = s
			}
		}
		return out
	default:
		return nil
	}
}
