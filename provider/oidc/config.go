package oidc

import (
	"net/url"
	"strings"
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
	if strings.TrimSpace(p.Key) == "" {
		return cloneWithProvider(ErrInvalidConfig, p.Key, map[string]any{"field": "key"})
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
	redirectURL, err := url.Parse(p.RedirectURL)
	if err != nil || redirectURL.Scheme == "" || redirectURL.Host == "" {
		metadata["field"] = "redirect_url"
		metadata["value"] = p.RedirectURL
		return cloneWithProvider(ErrInvalidConfig, p.Key, metadata)
	}
	return nil
}

func normalizeProviderKey(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}
