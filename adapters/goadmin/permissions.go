package goadmin

import (
	"context"
	"fmt"
	"strings"

	auth "github.com/goliatone/go-auth"
)

var defaultPermissionClaimKeys = []string{
	"permissions",
	"permission",
	"permission_list",
	"permissions_list",
	"scopes",
	"scope",
}

var defaultRoleClaimKeys = []string{"roles", "role"}
var defaultGroupClaimKeys = []string{"groups", "group"}

// ClaimPermissionConfig maps IdP claim hints into canonical go-admin permissions.
type ClaimPermissionConfig struct {
	PermissionClaimKeys []string
	RoleClaimKeys       []string
	GroupClaimKeys      []string
	PermissionMap       map[string]string
	RolePermissions     map[string][]string
	GroupPermissions    map[string][]string
	AllowUnmappedClaims bool
}

// ClaimPermissionResolver resolves go-admin permissions from go-auth JWT claims.
type ClaimPermissionResolver struct {
	cfg ClaimPermissionConfig
}

// NewClaimPermissionResolver builds a resolver suitable for
// admin.GoAuthAuthorizerConfig.ResolvePermissions.
func NewClaimPermissionResolver(cfg ClaimPermissionConfig) *ClaimPermissionResolver {
	cfg.PermissionClaimKeys = defaultStrings(cfg.PermissionClaimKeys, defaultPermissionClaimKeys)
	cfg.RoleClaimKeys = defaultStrings(cfg.RoleClaimKeys, defaultRoleClaimKeys)
	cfg.GroupClaimKeys = defaultStrings(cfg.GroupClaimKeys, defaultGroupClaimKeys)
	cfg.PermissionMap = normalizeStringMap(cfg.PermissionMap)
	cfg.RolePermissions = normalizePermissionMap(cfg.RolePermissions)
	cfg.GroupPermissions = normalizePermissionMap(cfg.GroupPermissions)
	return &ClaimPermissionResolver{cfg: cfg}
}

// ResolvePermissions resolves permissions for the current request context.
func (r *ClaimPermissionResolver) ResolvePermissions(ctx context.Context) ([]string, error) {
	if r == nil {
		return nil, fmt.Errorf("claim permission resolver is not configured")
	}
	claims, ok := auth.GetClaims(ctx)
	if !ok || claims == nil {
		return nil, nil
	}
	metadata := claimsMetadata(claims)
	out := map[string]struct{}{}

	for _, raw := range valuesForKeys(metadata, r.cfg.PermissionClaimKeys) {
		if mapped := r.mapPermission(raw); mapped != "" {
			out[mapped] = struct{}{}
		}
	}
	for _, role := range valuesForKeys(metadata, r.cfg.RoleClaimKeys) {
		for _, permission := range r.cfg.RolePermissions[normalizeKey(role)] {
			out[permission] = struct{}{}
		}
	}
	for _, group := range valuesForKeys(metadata, r.cfg.GroupClaimKeys) {
		for _, permission := range r.cfg.GroupPermissions[normalizeKey(group)] {
			out[permission] = struct{}{}
		}
	}

	return sortedPermissions(out), nil
}

// SSOMetadataFromContext exposes tenant and organization metadata to host policy.
func SSOMetadataFromContext(ctx context.Context) map[string]string {
	claims, ok := auth.GetClaims(ctx)
	if !ok || claims == nil {
		return nil
	}
	metadata := claimsMetadata(claims)
	out := map[string]string{}
	for _, key := range []string{"tenant_id", "tenant", "organization_id", "org_id", "organization"} {
		if value := firstString(metadata[key]); value != "" {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (r *ClaimPermissionResolver) mapPermission(raw string) string {
	key := normalizeKey(raw)
	if key == "" {
		return ""
	}
	if mapped := strings.TrimSpace(r.cfg.PermissionMap[key]); mapped != "" {
		return mapped
	}
	if r.cfg.AllowUnmappedClaims {
		return strings.TrimSpace(raw)
	}
	return ""
}

type metadataClaimser interface {
	ClaimsMetadata() map[string]any
}

func claimsMetadata(claims auth.AuthClaims) map[string]any {
	if claims == nil {
		return nil
	}
	if withMetadata, ok := claims.(metadataClaimser); ok {
		return withMetadata.ClaimsMetadata()
	}
	return nil
}

func valuesForKeys(metadata map[string]any, keys []string) []string {
	if len(metadata) == 0 {
		return nil
	}
	values := []string{}
	for _, key := range keys {
		values = append(values, stringsFromAny(metadata[strings.TrimSpace(key)])...)
	}
	return values
}

func stringsFromAny(value any) []string {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		return splitClaimString(v)
	case []string:
		return compactStrings(v)
	case []any:
		out := []string{}
		for _, item := range v {
			out = append(out, stringsFromAny(item)...)
		}
		return out
	default:
		return splitClaimString(fmt.Sprint(v))
	}
}

func splitClaimString(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' '
	})
	return compactStrings(parts)
}

func compactStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func defaultStrings(values, defaults []string) []string {
	values = compactStrings(values)
	if len(values) == 0 {
		return append([]string{}, defaults...)
	}
	return values
}

func normalizeStringMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range in {
		if normalized := normalizeKey(key); normalized != "" && strings.TrimSpace(value) != "" {
			out[normalized] = strings.TrimSpace(value)
		}
	}
	return out
}

func normalizePermissionMap(in map[string][]string) map[string][]string {
	out := map[string][]string{}
	for key, values := range in {
		normalized := normalizeKey(key)
		permissions := compactStrings(values)
		if normalized != "" && len(permissions) > 0 {
			out[normalized] = permissions
		}
	}
	return out
}

func normalizeKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func sortedPermissions(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for permission := range set {
		out = append(out, permission)
	}
	sortStrings(out)
	return out
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func firstString(value any) string {
	values := stringsFromAny(value)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
