package google

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goliatone/go-auth/social"
)

const (
	defaultAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	defaultTokenURL    = "https://oauth2.googleapis.com/token"
	defaultUserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
)

// Config holds Google OAuth configuration.
type Config struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
	Scopes       []string

	AuthURL     string
	TokenURL    string
	UserInfoURL string

	HTTPClient *http.Client
}

// DefaultScopes returns the default Google scopes.
func DefaultScopes() []string {
	return []string{"openid", "email", "profile"}
}

// Provider implements social.SocialProvider for Google.
type Provider struct {
	config     Config
	httpClient *http.Client
}

// New creates a new Google provider.
func New(cfg Config) *Provider {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = DefaultScopes()
	}
	if cfg.AuthURL == "" {
		cfg.AuthURL = defaultAuthURL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = defaultTokenURL
	}
	if cfg.UserInfoURL == "" {
		cfg.UserInfoURL = defaultUserInfoURL
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	return &Provider{
		config:     cfg,
		httpClient: client,
	}
}

// Name implements social.SocialProvider.
func (p *Provider) Name() string {
	return "google"
}

// AuthCodeURL implements social.SocialProvider.
func (p *Provider) AuthCodeURL(state string, opts ...social.AuthCodeOption) string {
	cfg := social.ApplyAuthCodeOptions(p.config.Scopes, opts...)
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes()
	}

	params := url.Values{
		"client_id":     {p.config.ClientID},
		"redirect_uri":  {p.config.CallbackURL},
		"response_type": {"code"},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {state},
		"access_type":   {"offline"},
	}

	if cfg.CodeChallenge != "" {
		method := cfg.CodeChallengeMethod
		if method == "" {
			method = "S256"
		}
		params.Set("code_challenge", cfg.CodeChallenge)
		params.Set("code_challenge_method", method)
	}

	if cfg.Prompt != "" {
		params.Set("prompt", cfg.Prompt)
	}

	return p.config.AuthURL + "?" + params.Encode()
}

// Exchange implements social.SocialProvider.
func (p *Provider) Exchange(ctx context.Context, code string, opts ...social.ExchangeOption) (*social.Token, error) {
	cfg := social.ApplyExchangeOptions(opts...)

	data := url.Values{
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
		"code":          {code},
		"redirect_uri":  {p.config.CallbackURL},
		"grant_type":    {"authorization_code"},
	}

	if cfg.CodeVerifier != "" {
		data.Set("code_verifier", cfg.CodeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp googleTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, providerError("exchange", resp.StatusCode, "invalid_response", "failed to decode token response", err, nil)
	}

	if resp.StatusCode != http.StatusOK || tokenResp.Error != "" {
		code, desc, raw := tokenResp.Error, tokenResp.ErrorDesc, tokenResp.errorMetadata()
		if code == "" && desc == "" {
			code, desc, raw = parseGoogleError(body)
		}
		return nil, providerError("exchange", resp.StatusCode, code, desc, nil, raw)
	}
	if tokenResp.AccessToken == "" {
		return nil, providerError("exchange", resp.StatusCode, "missing_access_token", "missing access token", nil, nil)
	}

	expiresAt := time.Time{}
	if tokenResp.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return &social.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    expiresAt,
		Scopes:       splitSpaceScopes(tokenResp.Scope),
		Raw: map[string]any{
			"id_token": tokenResp.IDToken,
		},
	}, nil
}

// UserInfo implements social.SocialProvider.
func (p *Provider) UserInfo(ctx context.Context, token *social.Token) (*social.SocialProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.config.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		code, description, raw := parseGoogleError(body)
		return nil, providerError("user_info", resp.StatusCode, code, description, nil, raw)
	}

	var userInfo googleUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, providerError("user_info", resp.StatusCode, "invalid_response", "failed to decode userinfo response", err, nil)
	}

	return mapProfile(&userInfo), nil
}

// ValidateToken implements social.SocialProvider.
func (p *Provider) ValidateToken(ctx context.Context, token *social.Token) error {
	if !token.ExpiresAt.IsZero() && time.Now().After(token.ExpiresAt) {
		return fmt.Errorf("google: token expired")
	}
	return nil
}

// RefreshToken implements social.SocialProvider.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (*social.Token, error) {
	data := url.Values{
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
		"refresh_token": {refreshToken},
		"grant_type":    {"refresh_token"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp googleTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, providerError("refresh", resp.StatusCode, "invalid_response", "failed to decode refresh response", err, nil)
	}

	if resp.StatusCode != http.StatusOK || tokenResp.Error != "" {
		code, desc, raw := tokenResp.Error, tokenResp.ErrorDesc, tokenResp.errorMetadata()
		if code == "" && desc == "" {
			code, desc, raw = parseGoogleError(body)
		}
		return nil, providerError("refresh", resp.StatusCode, code, desc, nil, raw)
	}
	if tokenResp.AccessToken == "" {
		return nil, providerError("refresh", resp.StatusCode, "missing_access_token", "missing access token", nil, nil)
	}

	expiresAt := time.Time{}
	if tokenResp.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return &social.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		Scopes:       splitSpaceScopes(tokenResp.Scope),
	}, nil
}

type googleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func (r googleTokenResponse) errorMetadata() map[string]any {
	meta := map[string]any{}
	if r.Error != "" {
		meta["error"] = r.Error
	}
	if r.ErrorDesc != "" {
		meta["error_description"] = r.ErrorDesc
	}
	if r.Scope != "" {
		meta["scope"] = r.Scope
	}
	return meta
}

type googleErrorResponse struct {
	Error string `json:"error"`
	Desc  string `json:"error_description"`
}

type googleAPIError struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

func parseGoogleError(body []byte) (string, string, map[string]any) {
	var plain googleErrorResponse
	if err := json.Unmarshal(body, &plain); err == nil && (plain.Error != "" || plain.Desc != "") {
		return plain.Error, plain.Desc, map[string]any{
			"error":             plain.Error,
			"error_description": plain.Desc,
		}
	}

	var api googleAPIError
	if err := json.Unmarshal(body, &api); err == nil && (api.Error.Message != "" || api.Error.Status != "") {
		code := api.Error.Status
		if code == "" && api.Error.Code != 0 {
			code = fmt.Sprintf("%d", api.Error.Code)
		}
		return code, api.Error.Message, map[string]any{
			"status":  api.Error.Status,
			"message": api.Error.Message,
			"code":    api.Error.Code,
		}
	}

	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = "google request failed"
	}

	return "", msg, nil
}

func splitSpaceScopes(scopes string) []string {
	if scopes == "" {
		return nil
	}

	parts := strings.Fields(scopes)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}

	return out
}

func providerError(operation string, status int, code, description string, err error, raw map[string]any) *social.ProviderError {
	return &social.ProviderError{
		Provider:    "google",
		Operation:   operation,
		Status:      status,
		Code:        code,
		Description: description,
		Err:         err,
		Raw:         raw,
	}
}
