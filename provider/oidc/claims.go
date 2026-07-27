package oidc

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
)

type DefaultClaimsMapper struct{}

type DefaultPrincipalMapper struct{}

//nolint:gocyclo // Principal integrity checks remain explicit so forged-field failures identify the exact boundary.
func validateMappedPrincipal(
	ctx context.Context,
	provider ProviderConfig,
	idToken auth.ValidatedTokenContext,
	accessToken *auth.ValidatedTokenContext,
	idClaims jwt.MapClaims,
	accessClaims jwt.MapClaims,
	userInfo map[string]any,
	mapped ValidatedProviderIdentity,
) (ValidatedProviderIdentity, error) {
	canonical, err := (DefaultPrincipalMapper{}).MapPrincipal(
		ctx,
		provider,
		idToken,
		accessToken,
		idClaims,
		accessClaims,
		userInfo,
	)
	if err != nil {
		return ValidatedProviderIdentity{}, err
	}

	if mapped.Provider != canonical.Provider || mapped.Subject != canonical.Subject {
		return ValidatedProviderIdentity{}, forgedPrincipalFieldError(provider.Key, "provider_subject")
	}
	for field, values := range map[string][2]string{
		"provider_session_id": {mapped.ProviderSessionID, canonical.ProviderSessionID},
		"client_id":           {mapped.ClientID, canonical.ClientID},
		"assurance_level":     {mapped.AssuranceLevel, canonical.AssuranceLevel},
		"tenant_id":           {mapped.TenantID, canonical.TenantID},
		"organization_id":     {mapped.OrganizationID, canonical.OrganizationID},
		"token_id":            {mapped.TokenID, canonical.TokenID},
		"permission_version":  {mapped.PermissionVersion, canonical.PermissionVersion},
	} {
		if values[0] != "" && values[0] != values[1] {
			return ValidatedProviderIdentity{}, forgedPrincipalFieldError(provider.Key, field)
		}
	}
	for field, values := range map[string][2]time.Time{
		"authentication_time": {mapped.AuthenticationAt, canonical.AuthenticationAt},
		"issued_at":           {mapped.IssuedAt, canonical.IssuedAt},
		"expires_at":          {mapped.ExpiresAt, canonical.ExpiresAt},
	} {
		if !values[0].IsZero() && !values[0].Equal(values[1]) {
			return ValidatedProviderIdentity{}, forgedPrincipalFieldError(provider.Key, field)
		}
	}
	if len(mapped.AssuranceMethods) > 0 && !slices.Equal(mapped.AssuranceMethods, canonical.AssuranceMethods) {
		return ValidatedProviderIdentity{}, forgedPrincipalFieldError(provider.Key, "assurance_methods")
	}
	if len(mapped.ResourceRoles) > 0 && !maps.Equal(mapped.ResourceRoles, canonical.ResourceRoles) {
		return ValidatedProviderIdentity{}, forgedPrincipalFieldError(provider.Key, "resource_roles")
	}
	if mapped.EmailVerified && !canonical.EmailVerified {
		return ValidatedProviderIdentity{}, forgedPrincipalFieldError(provider.Key, "email_verified")
	}

	// Custom mappers may shape profile data and application metadata. Security
	// context always comes from the already validated token contexts above.
	for target, value := range map[*string]string{
		&canonical.Email:      mapped.Email,
		&canonical.Name:       mapped.Name,
		&canonical.GivenName:  mapped.GivenName,
		&canonical.FamilyName: mapped.FamilyName,
		&canonical.Nickname:   mapped.Nickname,
		&canonical.Picture:    mapped.Picture,
	} {
		if value != "" {
			*target = value
		}
	}
	if mapped.Metadata != nil {
		canonical.Metadata = maps.Clone(mapped.Metadata)
	}
	if _, err := principalFromValidated("_mapper_validation_", canonical); err != nil {
		return ValidatedProviderIdentity{}, forgedPrincipalFieldError(provider.Key, "metadata")
	}
	return canonical, nil
}

func forgedPrincipalFieldError(providerKey, field string) error {
	return cloneWithProvider(ErrInvalidIDToken, providerKey, map[string]any{
		"cause": "principal mapper attempted to override validated security context",
		"field": field,
	})
}

//nolint:gocyclo // Claim-source precedence and integrity checks are intentionally explicit.
func (DefaultPrincipalMapper) MapPrincipal(_ context.Context, provider ProviderConfig, idToken auth.ValidatedTokenContext, accessToken *auth.ValidatedTokenContext, idClaims jwt.MapClaims, _ jwt.MapClaims, userInfo map[string]any) (ValidatedProviderIdentity, error) {
	if strings.TrimSpace(idToken.Subject) == "" {
		return ValidatedProviderIdentity{}, auth.ErrUnableToMapClaims
	}
	var err error
	userInfo, err = correlatedProfileUserInfo(provider.Key, idClaims, userInfo)
	if err != nil {
		return ValidatedProviderIdentity{}, err
	}
	if accessToken != nil {
		if accessToken.Subject != "" && accessToken.Subject != idToken.Subject {
			return ValidatedProviderIdentity{}, cloneWithProvider(ErrInvalidIDToken, provider.Key, map[string]any{"cause": "access token subject mismatch"})
		}
		if accessToken.Issuer != "" && accessToken.Issuer != idToken.Issuer {
			return ValidatedProviderIdentity{}, cloneWithProvider(ErrInvalidIDToken, provider.Key, map[string]any{"cause": "access token issuer mismatch"})
		}
		for name, pair := range map[string][2]string{
			"client_id":       {idToken.ClientID, accessToken.ClientID},
			"session_id":      {idToken.SessionID, accessToken.SessionID},
			"tenant_id":       {idToken.TenantID, accessToken.TenantID},
			"organization_id": {idToken.OrganizationID, accessToken.OrganizationID},
		} {
			if pair[0] != "" && pair[1] != "" && pair[0] != pair[1] {
				return ValidatedProviderIdentity{}, cloneWithProvider(ErrInvalidIDToken, provider.Key, map[string]any{"cause": name + " claim conflict"})
			}
		}
	}

	identity := ValidatedProviderIdentity{
		Provider:          provider.Key,
		Subject:           idToken.Subject,
		ProviderSessionID: idToken.SessionID,
		ClientID:          idToken.ClientID,
		AssuranceLevel:    idToken.AssuranceLevel,
		AssuranceMethods:  append([]string(nil), idToken.AssuranceMethods...),
		AuthenticationAt:  idToken.AuthenticationAt,
		IssuedAt:          idToken.IssuedAt,
		ExpiresAt:         idToken.ExpiresAt,
		TokenID:           idToken.TokenID,
		TenantID:          idToken.TenantID,
		OrganizationID:    idToken.OrganizationID,
		PermissionVersion: idToken.PermissionVersion,
		ResourceRoles:     mapStringClaim(idClaims, claimKeys(provider.ClaimKeys.ResourceRoles, "resource_roles")),
		Metadata:          map[string]string{},
		Provenance: map[string]ClaimSource{
			"subject": ClaimSourceIDToken,
		},
	}
	if identity.ClientID == "" {
		identity.ClientID = strings.TrimSpace(provider.ClientID)
	}
	if accessToken != nil {
		mergeAuthoritativeContext(&identity, *accessToken)
	}
	identity.Name, identity.Provenance["name"] = profileStringClaim(idClaims, userInfo, "name")
	identity.GivenName, identity.Provenance["given_name"] = profileStringClaim(idClaims, userInfo, "given_name")
	identity.FamilyName, identity.Provenance["family_name"] = profileStringClaim(idClaims, userInfo, "family_name")
	identity.Nickname, identity.Provenance["nickname"] = profileStringClaim(idClaims, userInfo, "nickname")
	identity.Picture, identity.Provenance["picture"] = profileStringClaim(idClaims, userInfo, "picture")
	email, emailVerified, emailSource, verificationSource := profileEmailClaim(idClaims, userInfo)
	identity.Email = email
	identity.EmailVerified = emailVerified
	if emailSource != "" {
		identity.Provenance["email"] = emailSource
	}
	if verificationSource != "" {
		identity.Provenance["email_verified"] = verificationSource
	}
	return identity, nil
}

var userInfoProfileStringClaims = [...]string{
	"email",
	"name",
	"given_name",
	"family_name",
	"nickname",
	"picture",
}

// correlatedProfileUserInfo enforces the OIDC subject binding before returning
// a typed, profile-only copy safe to pass to either built-in or custom mappers.
func correlatedProfileUserInfo(providerKey string, idClaims jwt.MapClaims, userInfo map[string]any) (map[string]any, error) {
	if userInfo == nil {
		return nil, nil
	}
	idSubject, _ := idClaims["sub"].(string)
	userInfoSubject, _ := userInfo["sub"].(string)
	if idSubject == "" || userInfoSubject == "" || userInfoSubject != idSubject {
		return nil, cloneWithProvider(ErrInvalidIDToken, providerKey, map[string]any{"cause": "userinfo subject mismatch"})
	}

	profile := make(map[string]any, len(userInfoProfileStringClaims)+2)
	profile["sub"] = userInfoSubject
	for _, claim := range userInfoProfileStringClaims {
		if value, ok := userInfo[claim].(string); ok {
			profile[claim] = value
		}
	}
	if value, ok := userInfo["email_verified"].(bool); ok {
		profile["email_verified"] = value
	}
	return profile, nil
}

func profileStringClaim(idClaims jwt.MapClaims, userInfo map[string]any, key string) (string, ClaimSource) {
	if value, _ := userInfo[key].(string); value != "" {
		return value, ClaimSourceUserInfo
	}
	if value, _ := idClaims[key].(string); value != "" {
		return value, ClaimSourceIDToken
	}
	return "", ""
}

func profileEmailClaim(idClaims jwt.MapClaims, userInfo map[string]any) (string, bool, ClaimSource, ClaimSource) {
	if email, _ := userInfo["email"].(string); email != "" {
		verified, hasVerification := userInfo["email_verified"].(bool)
		if !hasVerification {
			return email, false, ClaimSourceUserInfo, ""
		}
		return email, verified, ClaimSourceUserInfo, ClaimSourceUserInfo
	}
	email, _ := idClaims["email"].(string)
	if email == "" {
		return "", false, "", ""
	}
	verified, hasVerification := idClaims["email_verified"].(bool)
	if !hasVerification {
		return email, false, ClaimSourceIDToken, ""
	}
	return email, verified, ClaimSourceIDToken, ClaimSourceIDToken
}

func mergeAuthoritativeContext(identity *ValidatedProviderIdentity, access auth.ValidatedTokenContext) {
	if identity == nil {
		return
	}
	type stringField struct {
		target *string
		value  string
		name   string
	}
	for _, field := range []stringField{
		{&identity.ProviderSessionID, access.SessionID, "provider_session_id"},
		{&identity.ClientID, access.ClientID, "client_id"},
		{&identity.AssuranceLevel, access.AssuranceLevel, "assurance_level"},
		{&identity.TenantID, access.TenantID, "tenant_id"},
		{&identity.OrganizationID, access.OrganizationID, "organization_id"},
		{&identity.PermissionVersion, access.PermissionVersion, "permission_version"},
	} {
		if field.value != "" {
			*field.target = field.value
			identity.Provenance[field.name] = ClaimSourceAccessToken
		}
	}
	if len(access.AssuranceMethods) > 0 {
		identity.AssuranceMethods = append([]string(nil), access.AssuranceMethods...)
		identity.Provenance["assurance_methods"] = ClaimSourceAccessToken
	}
	if !access.AuthenticationAt.IsZero() {
		identity.AuthenticationAt = access.AuthenticationAt
		identity.Provenance["authentication_time"] = ClaimSourceAccessToken
	}
}

func validatedTokenContext(claims jwt.MapClaims) (auth.ValidatedTokenContext, error) {
	if claims == nil {
		return auth.ValidatedTokenContext{}, fmt.Errorf("%w: missing validated claims", auth.ErrInvalidPrincipal)
	}
	subject, _ := claims["sub"].(string)
	issuer, _ := claims["iss"].(string)
	if strings.TrimSpace(subject) == "" || strings.TrimSpace(issuer) == "" {
		return auth.ValidatedTokenContext{}, fmt.Errorf("%w: issuer and subject are required", auth.ErrInvalidPrincipal)
	}
	audiences, _ := claims.GetAudience()
	issuedAt, _ := claims.GetIssuedAt()
	expiresAt, _ := claims.GetExpirationTime()
	context := auth.ValidatedTokenContext{
		Issuer:            issuer,
		Subject:           subject,
		Audiences:         append([]string(nil), audiences...),
		SessionID:         firstTypedString(claims, "sid", "session_id"),
		ClientID:          firstTypedString(claims, "client_id", "azp"),
		AssuranceLevel:    firstTypedString(claims, "acr", "aal"),
		AssuranceMethods:  normalizeStringSlice(claims["amr"]),
		AuthenticationAt:  numericDateClaim(claims["auth_time"]),
		TokenID:           firstTypedString(claims, "jti"),
		TenantID:          firstTypedString(claims, "tenant_id"),
		OrganizationID:    firstTypedString(claims, "organization_id", "org_id"),
		PermissionVersion: firstTypedString(claims, "permission_version", "permissions_version"),
	}
	if issuedAt != nil {
		context.IssuedAt = issuedAt.Time
	}
	if expiresAt != nil {
		context.ExpiresAt = expiresAt.Time
	}
	return context, nil
}

func validatedIDTokenContext(claims jwt.MapClaims, provider ProviderConfig) (auth.ValidatedTokenContext, error) {
	context, err := validatedTokenContext(claims)
	if err != nil {
		return auth.ValidatedTokenContext{}, err
	}
	context.ClientID = firstTypedString(claims, "azp")
	if context.ClientID == "" {
		context.ClientID = strings.TrimSpace(provider.ClientID)
	}
	return context, nil
}

func firstTypedString(claims jwt.MapClaims, keys ...string) string {
	for _, key := range keys {
		if value, _ := claims[key].(string); strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func numericDateClaim(raw any) time.Time {
	switch value := raw.(type) {
	case float64:
		return time.Unix(int64(value), 0)
	case int64:
		return time.Unix(value, 0)
	case jsonNumber:
		parsed, err := value.Int64()
		if err == nil {
			return time.Unix(parsed, 0)
		}
	}
	return time.Time{}
}

type jsonNumber interface {
	Int64() (int64, error)
}

func (DefaultClaimsMapper) MapClaims(_ context.Context, provider ProviderConfig, claims jwt.MapClaims, userInfo map[string]any) (ExternalIdentity, *auth.JWTClaims, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return ExternalIdentity{}, nil, auth.ErrUnableToMapClaims
	}
	var err error
	userInfo, err = correlatedProfileUserInfo(provider.Key, claims, userInfo)
	if err != nil {
		return ExternalIdentity{}, nil, err
	}

	email, emailVerified, _, _ := profileEmailClaim(claims, userInfo)
	identity := ExternalIdentity{
		Provider:      provider.Key,
		Subject:       sub,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          profileValue(claims, userInfo, "name"),
		GivenName:     profileValue(claims, userInfo, "given_name"),
		FamilyName:    profileValue(claims, userInfo, "family_name"),
		Nickname:      profileValue(claims, userInfo, "nickname"),
		Picture:       profileValue(claims, userInfo, "picture"),
		TenantID:      firstStringClaim(claims, claimKeys(provider.ClaimKeys.TenantID, "tenant_id")),
		OrganizationID: firstStringClaim(claims,
			claimKeys(provider.ClaimKeys.OrganizationID, "organization_id", "org_id"),
		),
		Roles:         sliceClaim(claims, claimKeys(provider.ClaimKeys.Roles, "roles", "role")),
		Permissions:   sliceClaim(claims, claimKeys(provider.ClaimKeys.Permissions, "permissions", "scope")),
		ResourceRoles: mapStringClaim(claims, claimKeys(provider.ClaimKeys.ResourceRoles, "resource_roles")),
		Metadata:      map[string]any{"provider": provider.Key},
	}
	groups := sliceClaim(claims, claimKeys(provider.ClaimKeys.Groups, "groups"))
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

func profileValue(claims jwt.MapClaims, userInfo map[string]any, key string) string {
	value, _ := profileStringClaim(claims, userInfo, key)
	return value
}

func claimKeys(configured []string, defaults ...string) []string {
	if len(configured) > 0 {
		return configured
	}
	return defaults
}

func firstStringClaim(claims jwt.MapClaims, keys []string) string {
	for _, key := range keys {
		if val, _ := claims[key].(string); val != "" {
			return val
		}
	}
	return ""
}

func sliceClaim(claims jwt.MapClaims, keys []string) []string {
	for _, key := range keys {
		raw, ok := claims[key]
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

func mapStringClaim(claims jwt.MapClaims, keys []string) map[string]string {
	for _, key := range keys {
		raw, ok := claims[key]
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
