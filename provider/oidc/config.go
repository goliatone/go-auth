package oidc

import (
	"strings"

	auth "github.com/goliatone/go-auth"
)

func (p ProviderConfig) normalizedScopes() []string {
	scopes := append([]string(nil), p.Scopes...)
	if len(scopes) == 0 {
		return []string{DefaultScopeOpenID, "profile", "email"}
	}

	hasOpenID := false
	for _, scope := range scopes {
		if strings.EqualFold(strings.TrimSpace(scope), DefaultScopeOpenID) {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		scopes = append([]string{DefaultScopeOpenID}, scopes...)
	}
	return scopes
}

func (p ProviderConfig) validate() error {
	metadata := map[string]any{"provider": p.Key}
	limits := p.Limits.normalized()
	if strings.TrimSpace(p.Key) == "" {
		return cloneWithProvider(ErrInvalidConfig, p.Key, map[string]any{"field": "key"})
	}
	if len(p.Key) > limits.ProviderKeyBytes {
		return cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "key", "cause": "provider key exceeds limit"})
	}
	if strings.TrimSpace(p.Issuer) == "" && strings.TrimSpace(p.DiscoveryURL) == "" {
		metadata["field"] = "issuer"
		return cloneWithProvider(ErrInvalidConfig, p.Key, metadata)
	}
	if strings.TrimSpace(p.ClientID) == "" {
		metadata["field"] = "client_id"
		return cloneWithProvider(ErrInvalidConfig, p.Key, metadata)
	}
	if strings.TrimSpace(p.RedirectURL) == "" {
		metadata["field"] = "redirect_url"
		return cloneWithProvider(ErrInvalidConfig, p.Key, metadata)
	}
	for _, endpoint := range []struct {
		field  string
		value  string
		issuer bool
	}{
		{field: "issuer", value: p.Issuer, issuer: true},
		{field: "discovery_url", value: p.DiscoveryURL},
		{field: "redirect_url", value: p.RedirectURL},
	} {
		if strings.TrimSpace(endpoint.value) == "" {
			continue
		}
		if err := validateProviderEndpoint(endpoint.value, p.AllowInsecureHTTP, endpoint.issuer); err != nil {
			return cloneWithProvider(ErrInvalidConfig, p.Key, map[string]any{
				"field": endpoint.field,
				"cause": "endpoint must use HTTPS or explicit loopback HTTP",
			})
		}
	}
	if len(p.RedirectURL) > limits.RedirectBytes {
		return cloneWithProvider(ErrInvalidConfig, p.Key, map[string]any{"field": "redirect_url", "cause": "redirect URL exceeds limit"})
	}
	if len(p.AdditionalAuthParam) > auth.DefaultPrincipalMetadataEntries {
		return cloneWithProvider(ErrInvalidConfig, p.Key, map[string]any{"field": "additional_auth_params", "cause": "too many entries"})
	}
	totalMetadataBytes := 0
	for key, value := range p.AdditionalAuthParam {
		if isReservedAuthorizationParameter(key) {
			return cloneWithProvider(ErrInvalidConfig, p.Key, map[string]any{
				"field": "additional_auth_params",
				"cause": "parameter is protocol-owned",
			})
		}
		totalMetadataBytes += len(key) + len(value)
	}
	if totalMetadataBytes > auth.DefaultPrincipalMetadataBytes {
		return cloneWithProvider(ErrInvalidConfig, p.Key, map[string]any{"field": "additional_auth_params", "cause": "metadata exceeds limit"})
	}
	return nil
}

func normalizeProviderKey(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}

func (p ProviderConfig) clientSecret() (auth.Secret, error) {
	legacy := strings.TrimSpace(p.ClientSecret)
	if !p.ClientSecretValue.IsZero() {
		if legacy != "" && legacy != p.ClientSecretValue.Reveal() {
			return auth.Secret{}, cloneWithProvider(ErrInvalidConfig, p.Key, map[string]any{"field": "client_secret", "cause": "conflicting secret fields"})
		}
		return p.ClientSecretValue, nil
	}
	return auth.NewSecret(legacy), nil
}

func resolveSecretValue(legacy string, value auth.Secret, field string) (auth.Secret, error) {
	legacy = strings.TrimSpace(legacy)
	if !value.IsZero() {
		if legacy != "" && legacy != value.Reveal() {
			return auth.Secret{}, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": field, "cause": "conflicting secret fields"})
		}
		return value, nil
	}
	return auth.NewSecret(legacy), nil
}

func (r TokenResponse) accessToken() (auth.Secret, error) {
	return resolveSecretValue(r.AccessToken, r.AccessTokenValue, "access_token")
}

func (r TokenResponse) idToken() (auth.Secret, error) {
	return resolveSecretValue(r.IDToken, r.IDTokenValue, "id_token")
}

func (r TokenResponse) refreshToken() (auth.Secret, error) {
	return resolveSecretValue(r.RefreshToken, r.RefreshTokenValue, "refresh_token")
}
