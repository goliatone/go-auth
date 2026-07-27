package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	auth "github.com/goliatone/go-auth"
)

type HTTPTokenExchanger struct {
	Client *http.Client
}

type HTTPUserInfoFetcher struct {
	Client *http.Client
}

func (f HTTPUserInfoFetcher) FetchUserInfo(ctx context.Context, provider ProviderConfig, metadata DiscoveryMetadata, accessToken string) (map[string]any, error) {
	client := f.Client
	client = noRedirectHTTPClient(client)
	endpoint := strings.TrimSpace(metadata.UserInfoEndpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("userinfo endpoint is required")
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("access token is required")
	}
	if err := validateEndpointSet(provider, []providerEndpoint{
		{field: "userinfo_endpoint", value: endpoint, required: true},
	}); err != nil {
		return nil, err
	}

	requestCtx, cancel := providerRequestContext(ctx, provider.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer closeBody(res.Body)
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("userinfo request failed with status %d", res.StatusCode)
	}

	var userInfo map[string]any
	if err := decodeBoundedJSON(res.Body, provider.Limits.normalized().UserInfoBodyBytes, &userInfo); err != nil {
		return nil, err
	}
	return userInfo, nil
}

func (e HTTPTokenExchanger) Exchange(ctx context.Context, provider ProviderConfig, metadata DiscoveryMetadata, code string, codeVerifier string) (TokenResponse, error) {
	client := e.Client
	client = noRedirectHTTPClient(client)
	if err := validateEndpointSet(provider, []providerEndpoint{
		{field: "token_endpoint", value: metadata.TokenEndpoint, required: true},
	}); err != nil {
		return TokenResponse{}, err
	}
	form := url.Values{}
	form.Set("grant_type", DefaultGrantType)
	form.Set("code", code)
	form.Set("redirect_uri", provider.RedirectURL)
	form.Set("code_verifier", codeVerifier)
	method, err := resolveTokenEndpointAuthMethod(provider, metadata)
	if err != nil {
		return TokenResponse{}, err
	}
	switch method {
	case TokenEndpointAuthNone:
		form.Set("client_id", provider.ClientID)
	case TokenEndpointAuthClientSecretBasic:
		// Authorization is applied after request construction.
	case TokenEndpointAuthClientSecretPost:
		clientSecret, _ := provider.clientSecret()
		form.Set("client_id", provider.ClientID)
		form.Set("client_secret", clientSecret.Reveal())
	}

	requestCtx, cancel := providerRequestContext(ctx, provider.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, metadata.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}
	if method == TokenEndpointAuthClientSecretBasic {
		clientSecret, _ := provider.clientSecret()
		req.SetBasicAuth(provider.ClientID, clientSecret.Reveal())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return TokenResponse{}, err
	}
	defer closeBody(res.Body)
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return TokenResponse{}, ErrTokenExchangeFailed
	}

	var wire struct {
		AccessToken      string `json:"access_token"`
		IDToken          string `json:"id_token"`
		RefreshToken     string `json:"refresh_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int64  `json:"expires_in"`
		RefreshExpiresIn int64  `json:"refresh_expires_in"`
		Scope            string `json:"scope"`
	}
	if err := decodeBoundedJSON(res.Body, provider.Limits.normalized().TokenBodyBytes, &wire); err != nil {
		return TokenResponse{}, err
	}
	limits := provider.Limits.normalized()
	for _, token := range []string{wire.AccessToken, wire.IDToken, wire.RefreshToken} {
		if err := validateEncodedTokenSize(token, limits.EncodedTokenBytes); err != nil {
			return TokenResponse{}, err
		}
	}
	return TokenResponse{
		AccessTokenValue:  auth.NewSecret(wire.AccessToken),
		IDTokenValue:      auth.NewSecret(wire.IDToken),
		RefreshTokenValue: auth.NewSecret(wire.RefreshToken),
		TokenType:         wire.TokenType,
		ExpiresIn:         wire.ExpiresIn,
		RefreshExpiresIn:  wire.RefreshExpiresIn,
		Scope:             wire.Scope,
	}, nil
}

func resolveTokenEndpointAuthMethod(provider ProviderConfig, metadata DiscoveryMetadata) (TokenEndpointAuthMethod, error) {
	clientSecret, err := provider.clientSecret()
	if err != nil {
		return "", err
	}
	method := provider.TokenEndpointAuthMethod
	if method == TokenEndpointAuthUnspecified {
		if clientSecret.IsZero() {
			return TokenEndpointAuthNone, nil
		}
		return TokenEndpointAuthClientSecretPost, nil
	}
	supported := metadata.TokenEndpointAuthMethods
	if len(supported) == 0 {
		supported = []string{string(TokenEndpointAuthClientSecretBasic)}
	}
	found := slices.Contains(supported, string(method))
	if !found {
		return "", cloneWithProvider(ErrInvalidConfig, provider.Key, map[string]any{"field": "token_endpoint_auth_method", "cause": "method is not advertised"})
	}
	switch method {
	case TokenEndpointAuthNone:
		if !clientSecret.IsZero() {
			return "", cloneWithProvider(ErrInvalidConfig, provider.Key, map[string]any{"field": "client_secret", "cause": "secret is not allowed for public clients"})
		}
	case TokenEndpointAuthClientSecretBasic, TokenEndpointAuthClientSecretPost:
		if clientSecret.IsZero() {
			return "", cloneWithProvider(ErrInvalidConfig, provider.Key, map[string]any{"field": "client_secret", "cause": "secret is required for confidential clients"})
		}
	default:
		return "", cloneWithProvider(ErrInvalidConfig, provider.Key, map[string]any{"field": "token_endpoint_auth_method"})
	}
	return method, nil
}
