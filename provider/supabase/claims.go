package supabase

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	"github.com/google/uuid"
)

// ClaimsMapper normalizes Supabase-specific session and assurance claims after
// generic OIDC has validated both tokens. Only explicitly allowlisted
// app_metadata values are copied; user_metadata is never authoritative.
type ClaimsMapper struct {
	AllowedHookClaims []string
	AllowedUserRoles  []string
}

//nolint:gocyclo,funlen // Supabase claim integrity and hook-claim filtering remain explicit and fail closed.
func (m ClaimsMapper) MapPrincipal(
	ctx context.Context,
	provider oidc.ProviderConfig,
	idToken auth.ValidatedTokenContext,
	accessToken *auth.ValidatedTokenContext,
	idClaims jwt.MapClaims,
	accessClaims jwt.MapClaims,
	userInfo map[string]any,
) (oidc.ValidatedProviderIdentity, error) {
	if provider.Key != ProviderKey || accessToken == nil {
		return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: validated Supabase ID and access tokens are required", auth.ErrUnableToMapClaims)
	}
	identity, err := (oidc.DefaultPrincipalMapper{}).MapPrincipal(
		ctx, provider, idToken, accessToken, idClaims, accessClaims, userInfo,
	)
	if err != nil {
		return oidc.ValidatedProviderIdentity{}, err
	}
	if _, err := uuid.Parse(identity.Subject); err != nil {
		return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: Supabase subject must be a UUID", auth.ErrUnableToMapClaims)
	}
	if strings.TrimSpace(identity.ProviderSessionID) == "" ||
		strings.TrimSpace(identity.ClientID) == "" ||
		identity.AuthenticationAt.IsZero() ||
		identity.IssuedAt.IsZero() ||
		identity.ExpiresAt.IsZero() ||
		!identity.IssuedAt.Before(identity.ExpiresAt) {
		return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: incomplete Supabase session claims", auth.ErrUnableToMapClaims)
	}
	if identity.AssuranceLevel != "aal1" && identity.AssuranceLevel != "aal2" {
		return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: invalid Supabase assurance level", auth.ErrUnableToMapClaims)
	}
	if len(identity.AssuranceMethods) == 0 {
		return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: Supabase authentication methods are required", auth.ErrUnableToMapClaims)
	}
	if idToken.AssuranceLevel != "" && accessToken.AssuranceLevel != "" &&
		idToken.AssuranceLevel != accessToken.AssuranceLevel {
		return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: Supabase assurance claim conflict", auth.ErrUnableToMapClaims)
	}
	if len(idToken.AssuranceMethods) > 0 && len(accessToken.AssuranceMethods) > 0 &&
		!sameStrings(idToken.AssuranceMethods, accessToken.AssuranceMethods) {
		return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: Supabase authentication-method claim conflict", auth.ErrUnableToMapClaims)
	}
	if !idToken.AuthenticationAt.IsZero() && !accessToken.AuthenticationAt.IsZero() &&
		!idToken.AuthenticationAt.Equal(accessToken.AuthenticationAt) {
		return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: Supabase authentication-time claim conflict", auth.ErrUnableToMapClaims)
	}
	for _, method := range identity.AssuranceMethods {
		if strings.TrimSpace(method) == "" || len(method) > 128 {
			return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: invalid Supabase authentication method", auth.ErrUnableToMapClaims)
		}
	}
	role, _ := accessClaims["role"].(string)
	role = strings.TrimSpace(role)
	if role == "" || len(role) > 128 || privilegedSupabaseRole(role) {
		return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: invalid Supabase role", auth.ErrUnableToMapClaims)
	}
	allowedRoles := compact(m.AllowedUserRoles)
	if len(allowedRoles) == 0 {
		allowedRoles = []string{"authenticated"}
	}
	if !containsString(allowedRoles, role) {
		return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: Supabase role is not allowed for a user session", auth.ErrUnableToMapClaims)
	}
	if idRole, _ := idClaims["role"].(string); strings.TrimSpace(idRole) != "" && strings.TrimSpace(idRole) != role {
		return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: Supabase role claim conflict", auth.ErrUnableToMapClaims)
	}
	if identity.Metadata == nil {
		identity.Metadata = map[string]string{}
	}
	identity.Metadata["provider_role"] = role
	identity.Provenance["provider_role"] = oidc.ClaimSourceAccessToken

	appMetadata, _ := accessClaims["app_metadata"].(map[string]any)
	for _, key := range compact(m.AllowedHookClaims) {
		if forbiddenHookClaim(key) {
			return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: unsafe hook claim allowlist", auth.ErrUnableToMapClaims)
		}
		value, ok := safeMetadataValue(appMetadata[key])
		if !ok {
			continue
		}
		if len(key)+len(value) > 1024 {
			return oidc.ValidatedProviderIdentity{}, fmt.Errorf("%w: hook claim exceeds limit", auth.ErrUnableToMapClaims)
		}
		identity.Metadata["hook."+key] = value
		identity.Provenance["hook."+key] = oidc.ClaimSourceAccessToken
	}
	return identity, nil
}

func privilegedSupabaseRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "anon", "service_role", "supabase_admin", "postgres", "authenticator", "dashboard_user":
		return true
	default:
		return false
	}
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func containsString(values []string, expected string) bool {
	return slices.Contains(values, expected)
}

func forbiddenHookClaim(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "role", "roles", "permission", "permissions", "aal", "amr",
		"account_state", "status", "suspended", "banned_until":
		return true
	default:
		return false
	}
}

func safeMetadataValue(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed), strings.TrimSpace(typed) != ""
	case bool:
		return strconv.FormatBool(typed), true
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64), true
	case int64:
		return strconv.FormatInt(typed, 10), true
	default:
		return "", false
	}
}

var _ oidc.PrincipalMapper = ClaimsMapper{}
