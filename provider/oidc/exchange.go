package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type HTTPTokenExchanger struct {
	Client *http.Client
}

type HTTPUserInfoFetcher struct {
	Client *http.Client
}

func (f HTTPUserInfoFetcher) FetchUserInfo(ctx context.Context, provider ProviderConfig, metadata DiscoveryMetadata, accessToken string) (map[string]any, error) {
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := strings.TrimSpace(metadata.UserInfoEndpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("userinfo endpoint is required")
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("access token is required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("userinfo request failed with status %d", res.StatusCode)
	}

	var userInfo map[string]any
	if err := json.NewDecoder(res.Body).Decode(&userInfo); err != nil {
		return nil, err
	}
	return userInfo, nil
}

func (e HTTPTokenExchanger) Exchange(ctx context.Context, provider ProviderConfig, metadata DiscoveryMetadata, code string, codeVerifier string) (TokenResponse, error) {
	client := e.Client
	if client == nil {
		client = http.DefaultClient
	}
	form := url.Values{}
	form.Set("grant_type", DefaultGrantType)
	form.Set("client_id", provider.ClientID)
	form.Set("code", code)
	form.Set("redirect_uri", provider.RedirectURL)
	form.Set("code_verifier", codeVerifier)
	if strings.TrimSpace(provider.ClientSecret) != "" {
		form.Set("client_secret", provider.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return TokenResponse{}, err
	}
	defer res.Body.Close()
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return TokenResponse{}, ErrTokenExchangeFailed
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(res.Body).Decode(&tokenResponse); err != nil {
		return TokenResponse{}, err
	}
	return tokenResponse, nil
}
