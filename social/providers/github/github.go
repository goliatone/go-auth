package github

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
	defaultAuthURL   = "https://github.com/login/oauth/authorize"
	defaultTokenURL  = "https://github.com/login/oauth/access_token"
	defaultUserURL   = "https://api.github.com/user"
	defaultEmailsURL = "https://api.github.com/user/emails"
)

// Config holds GitHub OAuth configuration.
type Config struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
	Scopes       []string

	AuthURL   string
	TokenURL  string
	UserURL   string
	EmailsURL string

	HTTPClient *http.Client
}

// DefaultScopes returns the default GitHub scopes.
func DefaultScopes() []string {
	return []string{"user:email", "read:user"}
}

// Provider implements social.SocialProvider for GitHub.
type Provider struct {
	config     Config
	httpClient *http.Client
}

// New creates a new GitHub provider.
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
	if cfg.UserURL == "" {
		cfg.UserURL = defaultUserURL
	}
	if cfg.EmailsURL == "" {
		cfg.EmailsURL = defaultEmailsURL
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
	return "github"
}

// AuthCodeURL implements social.SocialProvider.
func (p *Provider) AuthCodeURL(state string, opts ...social.AuthCodeOption) string {
	cfg := social.ApplyAuthCodeOptions(p.config.Scopes, opts...)
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes()
	}

	params := url.Values{
		"client_id":    {p.config.ClientID},
		"redirect_uri": {p.config.CallbackURL},
		"scope":        {strings.Join(scopes, " ")},
		"state":        {state},
	}

	if cfg.CodeChallenge != "" {
		method := cfg.CodeChallengeMethod
		if method == "" {
			method = "S256"
		}
		params.Set("code_challenge", cfg.CodeChallenge)
		params.Set("code_challenge_method", method)
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
	}
	if cfg.CodeVerifier != "" {
		data.Set("code_verifier", cfg.CodeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp githubTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, providerError("exchange", resp.StatusCode, "invalid_response", "failed to decode token response", err, nil)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, providerError("exchange", resp.StatusCode, tokenResp.Error, tokenResp.ErrorDesc, nil, tokenResp.errorMetadata())
	}
	if tokenResp.Error != "" {
		return nil, providerError("exchange", resp.StatusCode, tokenResp.Error, tokenResp.ErrorDesc, nil, tokenResp.errorMetadata())
	}
	if tokenResp.AccessToken == "" {
		return nil, providerError("exchange", resp.StatusCode, "missing_access_token", "missing access token", nil, nil)
	}

	return &social.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		Scopes:      splitCommaScopes(tokenResp.Scope),
	}, nil
}

// UserInfo implements social.SocialProvider.
func (p *Provider) UserInfo(ctx context.Context, token *social.Token) (*social.SocialProfile, error) {
	user, err := p.fetchUser(ctx, token.AccessToken)
	if err != nil {
		return nil, err
	}

	email, emailVerified, err := p.fetchPrimaryEmail(ctx, token.AccessToken)
	if err != nil {
		email = user.Email
	}

	return mapProfile(user, email, emailVerified), nil
}

// ValidateToken implements social.SocialProvider.
func (p *Provider) ValidateToken(ctx context.Context, token *social.Token) error {
	_, err := p.fetchUser(ctx, token.AccessToken)
	return err
}

// RefreshToken implements social.SocialProvider.
// GitHub tokens don't expire and can't be refreshed.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (*social.Token, error) {
	return nil, fmt.Errorf("github: token refresh not supported")
}

func (p *Provider) fetchUser(ctx context.Context, accessToken string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.config.UserURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

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
		return nil, providerError("user_info", resp.StatusCode, "", apiErrorMessage(body), nil, nil)
	}

	var user githubUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, providerError("user_info", resp.StatusCode, "invalid_response", "failed to decode user response", err, nil)
	}

	return &user, nil
}

func (p *Provider) fetchPrimaryEmail(ctx context.Context, accessToken string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.config.EmailsURL, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}

	if resp.StatusCode != http.StatusOK {
		return "", false, providerError("emails", resp.StatusCode, "", apiErrorMessage(body), nil, nil)
	}

	var emails []githubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", false, providerError("emails", resp.StatusCode, "invalid_response", "failed to decode emails response", err, nil)
	}

	for _, e := range emails {
		if e.Primary {
			return e.Email, e.Verified, nil
		}
	}

	for _, e := range emails {
		if e.Verified {
			return e.Email, true, nil
		}
	}

	return "", false, providerError("emails", resp.StatusCode, "email_not_found", "no valid email found", nil, nil)
}

type githubTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
	ErrorURI    string `json:"error_uri"`
}

func (r githubTokenResponse) errorMetadata() map[string]any {
	meta := map[string]any{}
	if r.Error != "" {
		meta["error"] = r.Error
	}
	if r.ErrorDesc != "" {
		meta["error_description"] = r.ErrorDesc
	}
	if r.ErrorURI != "" {
		meta["error_uri"] = r.ErrorURI
	}
	if r.Scope != "" {
		meta["scope"] = r.Scope
	}
	return meta
}

type githubAPIError struct {
	Message          string `json:"message"`
	DocumentationURL string `json:"documentation_url"`
}

func apiErrorMessage(body []byte) string {
	var apiErr githubAPIError
	if err := json.Unmarshal(body, &apiErr); err == nil && apiErr.Message != "" {
		return apiErr.Message
	}

	msg := strings.TrimSpace(string(body))
	if msg == "" {
		return "github request failed"
	}

	return msg
}

func splitCommaScopes(scopes string) []string {
	if scopes == "" {
		return nil
	}

	parts := strings.Split(scopes, ",")
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
		Provider:    "github",
		Operation:   operation,
		Status:      status,
		Code:        code,
		Description: description,
		Err:         err,
		Raw:         raw,
	}
}
