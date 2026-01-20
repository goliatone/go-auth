package auth0

import (
	"context"
	"strings"

	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/goliatone/go-auth"
)

// ClaimsMapper transforms external claims to go-auth JWTClaims.
type ClaimsMapper interface {
	// Map converts provider-specific claims to go-auth JWTClaims.
	// Implementations should populate RegisteredClaims, UID, UserRole,
	// Resources, and Metadata for full go-auth compatibility.
	Map(ctx context.Context, externalClaims any) (*auth.JWTClaims, error)
}

// Auth0ClaimsMapper maps Auth0 JWT claims to go-auth claims.
type Auth0ClaimsMapper struct {
	Namespace string

	DefaultRole           string
	PermissionToRoleMap   map[string]string
	ResourceRoleExtractor func(claims *Auth0CustomClaims) map[string]string

	RoleClaimKey          string
	PermissionsClaimKey   string
	ResourceRolesClaimKey string
	OrganizationClaimKey  string
	TenantClaimKey        string
}

// Map implements ClaimsMapper.
func (m *Auth0ClaimsMapper) Map(ctx context.Context, externalClaims any) (*auth.JWTClaims, error) {
	validated, ok := externalClaims.(*validator.ValidatedClaims)
	if !ok || validated == nil {
		return nil, auth.ErrUnableToMapClaims
	}

	customClaims, ok := validated.CustomClaims.(*Auth0CustomClaims)
	if !ok || customClaims == nil {
		customClaims = &Auth0CustomClaims{}
	}

	role := m.extractRole(customClaims)
	resourceRoles := m.extractResourceRoles(customClaims)
	permissions := m.permissionsFromClaims(customClaims)

	metadata := map[string]any{}
	if customClaims.Email != "" {
		metadata["email"] = customClaims.Email
	}
	if customClaims.EmailVerified {
		metadata["email_verified"] = customClaims.EmailVerified
	}
	if customClaims.Name != "" {
		metadata["name"] = customClaims.Name
	}
	if customClaims.Nickname != "" {
		metadata["nickname"] = customClaims.Nickname
	}
	if customClaims.Picture != "" {
		metadata["picture"] = customClaims.Picture
	}
	if len(permissions) > 0 {
		metadata["permissions"] = permissions
	}
	if customClaims.Scope != "" {
		metadata["scope"] = customClaims.Scope
	}
	if validated.RegisteredClaims.Subject != "" {
		metadata["auth0_sub"] = validated.RegisteredClaims.Subject
	}

	if orgID := m.extractOrganizationID(customClaims); orgID != "" {
		metadata["organization_id"] = orgID
	}
	if tenantID := m.extractTenantID(customClaims); tenantID != "" {
		metadata["tenant_id"] = tenantID
	}

	claims := &auth.JWTClaims{
		RegisteredClaims: validated.RegisteredClaims,
		UID:              validated.RegisteredClaims.Subject,
		UserRole:         role,
		Resources:        resourceRoles,
		Metadata:         metadata,
	}

	return claims, nil
}

func (m *Auth0ClaimsMapper) extractRole(claims *Auth0CustomClaims) string {
	role := m.claimString(claims, m.roleClaimKeys()...)
	if role != "" {
		return role
	}

	if m.PermissionToRoleMap != nil {
		for _, perm := range m.permissionsFromClaims(claims) {
			if mapped, ok := m.PermissionToRoleMap[perm]; ok {
				return mapped
			}
		}
	}

	if m.DefaultRole != "" {
		return m.DefaultRole
	}
	return string(auth.RoleMember)
}

func (m *Auth0ClaimsMapper) extractResourceRoles(claims *Auth0CustomClaims) map[string]string {
	if m.ResourceRoleExtractor != nil {
		return m.ResourceRoleExtractor(claims)
	}

	resourceRoles := m.claimMap(claims, m.resourceRoleClaimKeys()...)
	if len(resourceRoles) > 0 {
		return resourceRoles
	}

	if len(claims.ResourceRoles) > 0 {
		return claims.ResourceRoles
	}

	resourceRoles = make(map[string]string)
	for _, perm := range m.permissionsFromClaims(claims) {
		parts := strings.SplitN(perm, ":", 2)
		if len(parts) != 2 {
			continue
		}
		resource := strings.TrimSpace(parts[0])
		action := strings.TrimSpace(parts[1])
		if resource == "" {
			continue
		}
		resourceRoles[resource] = m.actionToRole(action)
	}

	if len(resourceRoles) == 0 {
		return nil
	}

	return resourceRoles
}

func (m *Auth0ClaimsMapper) permissionsFromClaims(claims *Auth0CustomClaims) []string {
	if claims == nil {
		return nil
	}

	if perms := m.claimSlice(claims, m.permissionsClaimKeys()...); len(perms) > 0 {
		return perms
	}

	if len(claims.Permissions) > 0 {
		return append([]string(nil), claims.Permissions...)
	}

	if claims.Scope != "" {
		return strings.Fields(claims.Scope)
	}

	return nil
}

func (m *Auth0ClaimsMapper) extractOrganizationID(claims *Auth0CustomClaims) string {
	keys := m.organizationClaimKeys()
	if org := m.claimString(claims, keys...); org != "" {
		return org
	}
	return ""
}

func (m *Auth0ClaimsMapper) extractTenantID(claims *Auth0CustomClaims) string {
	keys := m.tenantClaimKeys()
	if tenant := m.claimString(claims, keys...); tenant != "" {
		return tenant
	}
	return ""
}

func (m *Auth0ClaimsMapper) actionToRole(action string) string {
	switch action {
	case "delete", "admin":
		return string(auth.RoleOwner)
	case "create", "write":
		return string(auth.RoleAdmin)
	case "update", "edit":
		return string(auth.RoleMember)
	default:
		return string(auth.RoleGuest)
	}
}

func (m *Auth0ClaimsMapper) roleClaimKeys() []string {
	return uniqueKeys(
		m.RoleClaimKey,
		m.namespacedKey("role"),
		"role",
	)
}

func (m *Auth0ClaimsMapper) permissionsClaimKeys() []string {
	return uniqueKeys(
		m.PermissionsClaimKey,
		m.namespacedKey("permissions"),
		"permissions",
	)
}

func (m *Auth0ClaimsMapper) resourceRoleClaimKeys() []string {
	return uniqueKeys(
		m.ResourceRolesClaimKey,
		m.namespacedKey("resource_roles"),
		"resource_roles",
	)
}

func (m *Auth0ClaimsMapper) organizationClaimKeys() []string {
	return uniqueKeys(
		m.OrganizationClaimKey,
		m.namespacedKey("organization_id"),
		m.namespacedKey("org_id"),
		"organization_id",
		"org_id",
	)
}

func (m *Auth0ClaimsMapper) tenantClaimKeys() []string {
	return uniqueKeys(
		m.TenantClaimKey,
		m.namespacedKey("tenant_id"),
		"tenant_id",
	)
}

func (m *Auth0ClaimsMapper) claimString(claims *Auth0CustomClaims, keys ...string) string {
	for _, key := range keys {
		if key == "" {
			continue
		}
		if val, ok := claimValue(claims, key); ok {
			if str := stringFromAny(val); str != "" {
				return str
			}
		}
	}
	return ""
}

func (m *Auth0ClaimsMapper) claimSlice(claims *Auth0CustomClaims, keys ...string) []string {
	for _, key := range keys {
		if key == "" {
			continue
		}
		if val, ok := claimValue(claims, key); ok {
			if slice := stringSliceFromAny(val); len(slice) > 0 {
				return slice
			}
		}
	}
	return nil
}

func (m *Auth0ClaimsMapper) claimMap(claims *Auth0CustomClaims, keys ...string) map[string]string {
	for _, key := range keys {
		if key == "" {
			continue
		}
		if val, ok := claimValue(claims, key); ok {
			if mapped := mapStringStringFromAny(val); len(mapped) > 0 {
				return mapped
			}
		}
	}
	return nil
}

func (m *Auth0ClaimsMapper) namespacePrefix() string {
	namespace := strings.TrimSpace(m.Namespace)
	if namespace == "" {
		return ""
	}
	if strings.HasSuffix(namespace, "/") || strings.HasSuffix(namespace, ":") {
		return namespace
	}
	return namespace + "/"
}

func (m *Auth0ClaimsMapper) namespacedKey(key string) string {
	if key == "" {
		return ""
	}
	prefix := m.namespacePrefix()
	if prefix == "" {
		return ""
	}
	return prefix + key
}

func claimValue(claims *Auth0CustomClaims, key string) (any, bool) {
	if claims == nil || key == "" {
		return nil, false
	}
	if claims.Raw != nil {
		if val, ok := claims.Raw[key]; ok {
			return val, true
		}
	}
	if claims.Metadata != nil {
		if val, ok := claims.Metadata[key]; ok {
			return val, true
		}
	}
	return nil, false
}

func stringFromAny(val any) string {
	switch typed := val.(type) {
	case string:
		return typed
	}
	return ""
}

func stringSliceFromAny(val any) []string {
	switch typed := val.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, entry := range typed {
			if str, ok := entry.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, entry := range typed {
			if str, ok := entry.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	}
	return nil
}

func mapStringStringFromAny(val any) map[string]string {
	switch typed := val.(type) {
	case map[string]string:
		out := make(map[string]string, len(typed))
		for key, value := range typed {
			out[key] = value
		}
		return out
	case map[string]any:
		out := make(map[string]string, len(typed))
		for key, value := range typed {
			if str, ok := value.(string); ok {
				out[key] = str
			}
		}
		return out
	case map[string]interface{}:
		out := make(map[string]string, len(typed))
		for key, value := range typed {
			if str, ok := value.(string); ok {
				out[key] = str
			}
		}
		return out
	}
	return nil
}

func uniqueKeys(values ...string) []string {
	seen := map[string]struct{}{}
	keys := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		keys = append(keys, value)
	}
	return keys
}
