package supabase

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
)

type RefreshTokenValidator interface {
	ValidateIDToken(context.Context, string, string) (jwt.MapClaims, error)
	ValidateIDTokenWithAccessToken(context.Context, string, string, string) (jwt.MapClaims, error)
	ValidateAccessToken(context.Context, string) (jwt.MapClaims, error)
}

type SessionClient struct {
	client    *Client
	validator RefreshTokenValidator
	clock     func() time.Time
}

func NewSessionClient(client *Client, validator RefreshTokenValidator) (*SessionClient, error) {
	if client == nil || validator == nil {
		return nil, ErrInvalidConfig
	}
	return &SessionClient{
		client: client, validator: validator, clock: func() time.Time { return time.Now().UTC() },
	}, nil
}

//nolint:gocyclo // Refresh binding and ambiguity checks stay explicit to preserve fail-closed rotation.
func (s *SessionClient) RefreshProviderTokens(ctx context.Context, request auth.ProviderRefreshRequest) (auth.ProviderRefreshResult, error) {
	if s == nil || s.client == nil || s.validator == nil || request.RefreshToken.IsZero() ||
		strings.TrimSpace(request.AttemptID) == "" ||
		strings.TrimSpace(request.Session.ID) == "" ||
		request.CurrentTokens.RefreshToken().IsZero() ||
		request.RefreshToken.Reveal() != request.CurrentTokens.RefreshToken().Reveal() ||
		request.Session.Binding.Provider != ProviderKey ||
		strings.TrimRight(request.Session.Binding.Issuer, "/") != s.client.config.Issuer ||
		request.Session.Binding.ClientID != s.client.config.ClientID {
		return auth.ProviderRefreshResult{}, auth.ErrProviderRefreshRejected
	}
	values := url.Values{
		"refresh_token": {request.RefreshToken.Reveal()},
		"client_id":     {s.client.config.ClientID},
	}
	httpRequest, cancel, err := s.refreshRequest(ctx, values)
	if err != nil {
		return auth.ProviderRefreshResult{}, err
	}
	defer cancel()
	response, err := s.client.httpClient.Do(httpRequest)
	if err != nil {
		return auth.ProviderRefreshResult{}, auth.ErrProviderRefreshAmbiguous
	}
	defer func() {
		_ = response.Body.Close()
	}()
	payload, err := readBounded(response.Body, s.client.config.ResponseBodyBytes)
	if err != nil {
		return auth.ProviderRefreshResult{}, auth.ErrProviderRefreshAmbiguous
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if response.StatusCode == http.StatusBadRequest ||
			response.StatusCode == http.StatusUnauthorized ||
			response.StatusCode == http.StatusForbidden {
			return auth.ProviderRefreshResult{}, auth.ErrProviderRefreshRejected
		}
		return auth.ProviderRefreshResult{}, auth.ErrProviderRefreshAmbiguous
	}
	var tokenResponse refreshResponse
	if unmarshalErr := json.Unmarshal(payload, &tokenResponse); unmarshalErr != nil ||
		strings.TrimSpace(tokenResponse.AccessToken) == "" {
		return auth.ProviderRefreshResult{}, auth.ErrProviderRefreshAmbiguous
	}
	tokens, err := s.validatedTokenSet(ctx, request, tokenResponse)
	if err != nil {
		return auth.ProviderRefreshResult{}, err
	}
	return auth.ProviderRefreshResult{Tokens: tokens}, nil
}

func (s *SessionClient) refreshRequest(ctx context.Context, values url.Values) (*http.Request, context.CancelFunc, error) {
	endpoint, err := s.client.resolvePath("/auth/v1/token")
	if err != nil {
		return nil, func() {}, err
	}
	query := endpoint.Query()
	query.Set("grant_type", "refresh_token")
	endpoint.RawQuery = query.Encode()
	requestCtx, cancel := context.WithTimeout(ctx, s.client.config.RequestTimeout)
	request, err := http.NewRequestWithContext(
		requestCtx, http.MethodPost, endpoint.String(), strings.NewReader(values.Encode()),
	)
	if err != nil {
		cancel()
		return nil, func() {}, auth.ErrProviderRefreshAmbiguous
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Supabase-Api-Version", s.client.config.AuthAPIVersion)
	request.Header.Set("X-Supabase-OAuth-Version", s.client.config.OAuthAPIVersion)
	switch s.client.config.TokenEndpointAuthMethod {
	case oidc.TokenEndpointAuthNone:
		request.Header.Set("apikey", s.client.config.PublishableKey.Reveal())
	case oidc.TokenEndpointAuthClientSecretBasic:
		request.SetBasicAuth(s.client.config.ClientID, s.client.config.ClientSecret.Reveal())
	case oidc.TokenEndpointAuthClientSecretPost:
		values.Set("client_secret", s.client.config.ClientSecret.Reveal())
		request.Body = io.NopCloser(strings.NewReader(values.Encode()))
		request.ContentLength = int64(len(values.Encode()))
	default:
		cancel()
		return nil, func() {}, auth.ErrProviderRefreshRejected
	}
	return request, cancel, nil
}

//nolint:gocyclo // Every refreshed token and session binding is validated explicitly.
func (s *SessionClient) validatedTokenSet(
	ctx context.Context,
	request auth.ProviderRefreshRequest,
	response refreshResponse,
) (auth.ProviderTokenSet, error) {
	accessClaims, err := s.validator.ValidateAccessToken(ctx, response.AccessToken)
	if err != nil {
		return auth.ProviderTokenSet{}, auth.ErrProviderRefreshRejected
	}
	accessContext, err := refreshTokenContext(accessClaims)
	if err != nil {
		return auth.ProviderTokenSet{}, auth.ErrProviderRefreshRejected
	}
	if !s.validAccessContext(accessContext) ||
		claimString(accessClaims, "role") != "authenticated" ||
		accessContext.Subject != request.Session.Principal.ProviderSubject ||
		(request.Session.Principal.ProviderSessionID != "" &&
			accessContext.SessionID != request.Session.Principal.ProviderSessionID) {
		return auth.ProviderTokenSet{}, auth.ErrProviderRefreshRejected
	}
	var idContext *auth.ValidatedTokenContext
	idToken := auth.NewSecret(response.IDToken)
	if response.IDToken != "" {
		idClaims, validateErr := s.validator.ValidateIDTokenWithAccessToken(ctx, response.IDToken, "", response.AccessToken)
		if validateErr != nil {
			return auth.ProviderTokenSet{}, auth.ErrProviderRefreshRejected
		}
		validated, contextErr := refreshTokenContext(idClaims)
		if contextErr != nil || !s.validIDContext(validated) ||
			validated.Subject != accessContext.Subject ||
			(claimString(idClaims, "role") != "" &&
				claimString(idClaims, "role") != claimString(accessClaims, "role")) ||
			(validated.SessionID != "" && validated.SessionID != accessContext.SessionID) ||
			(validated.AssuranceLevel != "" && validated.AssuranceLevel != accessContext.AssuranceLevel) ||
			(!validated.AuthenticationAt.IsZero() && !validated.AuthenticationAt.Equal(accessContext.AuthenticationAt)) {
			return auth.ProviderTokenSet{}, auth.ErrProviderRefreshRejected
		}
		idContext = &validated
	} else {
		idToken = request.CurrentTokens.IDToken()
		if current, ok := request.CurrentTokens.IDContext(); ok {
			idContext = &current
		}
	}
	refreshToken := auth.NewSecret(response.RefreshToken)
	if response.RefreshToken == "" {
		refreshToken = request.CurrentTokens.RefreshToken()
	}
	now := s.clock()
	accessExpiresAt := accessContext.ExpiresAt
	if accessExpiresAt.IsZero() && response.ExpiresIn > 0 {
		accessExpiresAt = now.Add(time.Duration(response.ExpiresIn) * time.Second)
	}
	refreshExpiresAt := request.CurrentTokens.RefreshExpiresAt()
	if response.RefreshExpiresIn > 0 {
		refreshExpiresAt = now.Add(time.Duration(response.RefreshExpiresIn) * time.Second)
	}
	scopes := request.CurrentTokens.Scopes()
	if fields := strings.Fields(response.Scope); len(fields) > 0 {
		normalized := compact(fields)
		if len(normalized) != len(fields) {
			return auth.ProviderTokenSet{}, auth.ErrProviderRefreshRejected
		}
		for _, scope := range normalized {
			if !containsString(s.client.config.Scopes, scope) {
				return auth.ProviderTokenSet{}, auth.ErrProviderRefreshRejected
			}
		}
		scopes = fields
	}
	return auth.NewProviderTokenSet(auth.ProviderTokenSetInput{
		AccessToken:      auth.NewSecret(response.AccessToken),
		RefreshToken:     refreshToken,
		IDToken:          idToken,
		TokenType:        firstNonEmpty(response.TokenType, request.CurrentTokens.TokenType()),
		Scopes:           scopes,
		AcquiredAt:       now,
		AccessExpiresAt:  accessExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
		IDExpiresAt: func() time.Time {
			if idContext == nil {
				return time.Time{}
			}
			return idContext.ExpiresAt
		}(),
		IDContext:     idContext,
		AccessContext: &accessContext,
	})
}

func (s *SessionClient) ReconcileProviderRefresh(context.Context, auth.ProviderRefreshReconcileRequest) (auth.ProviderRefreshReconcileResult, error) {
	// Supabase does not expose rotated refresh-token material for authoritative
	// recovery. The provider-session owner must retain its uncertain state and
	// require fresh authentication.
	return auth.ProviderRefreshReconcileResult{Status: auth.ProviderRefreshReconcileUnknown}, nil
}

type SignOutScope string

const (
	SignOutCurrent SignOutScope = "local"
	SignOutAll     SignOutScope = "global"
	SignOutNamed   SignOutScope = "named"
)

//nolint:gocyclo,funlen // Remote revocation outcomes are mapped explicitly for safe retry behavior.
func (s *SessionClient) SignOut(ctx context.Context, tokens auth.ProviderTokenSet, scope SignOutScope) (auth.ProviderRemoteRevocationOutcome, error) {
	outcome := auth.ProviderRemoteRevocationOutcome{
		Status:                auth.ProviderRemoteRevocationFailed,
		ResidualAccessExpires: tokens.AccessExpiresAt(),
	}
	if s == nil || s.client == nil || tokens.AccessToken().IsZero() ||
		!s.validRevocationToken(tokens) {
		return outcome, auth.ErrProviderOperationUnauthorized
	}
	if scope == SignOutNamed {
		outcome.Status = auth.ProviderRemoteRevocationUnsupported
		return outcome, nil
	}
	if scope != SignOutCurrent && scope != SignOutAll {
		return outcome, auth.ErrProviderOperationInvalid
	}
	endpoint, err := s.client.resolvePath("/auth/v1/logout")
	if err != nil {
		return outcome, err
	}
	query := endpoint.Query()
	query.Set("scope", string(scope))
	endpoint.RawQuery = query.Encode()
	requestCtx, cancel := context.WithTimeout(ctx, s.client.config.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint.String(), nil)
	if err != nil {
		return outcome, ErrProviderUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken().Reveal())
	request.Header.Set("apikey", s.client.config.PublishableKey.Reveal())
	request.Header.Set("X-Supabase-Api-Version", s.client.config.AuthAPIVersion)
	response, err := s.client.httpClient.Do(request)
	if err != nil {
		outcome.Status, outcome.Retryable = auth.ProviderRemoteRevocationPending, true
		return outcome, ErrProviderUnavailable
	}
	defer func() {
		_ = response.Body.Close()
	}()
	_, readErr := readBounded(response.Body, s.client.config.ResponseBodyBytes)
	if readErr != nil {
		outcome.Status, outcome.Retryable = auth.ProviderRemoteRevocationPending, true
		return outcome, readErr
	}
	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		outcome.Status = auth.ProviderRemoteRevocationSucceeded
		return outcome, nil
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusNotFound:
		outcome.Status = auth.ProviderRemoteRevocationSucceeded
		return outcome, nil
	case response.StatusCode == http.StatusNotImplemented:
		outcome.Status = auth.ProviderRemoteRevocationUnsupported
		return outcome, nil
	default:
		outcome.Status = auth.ProviderRemoteRevocationPending
		outcome.Retryable = response.StatusCode == 429 || response.StatusCode >= 500
		return outcome, providerError(response.StatusCode, "", response.Header.Get("X-Request-ID"))
	}
}

func (s *SessionClient) validAccessContext(token auth.ValidatedTokenContext) bool {
	now := s.clock()
	return strings.TrimRight(token.Issuer, "/") == s.client.config.Issuer &&
		token.ClientID == s.client.config.ClientID &&
		strings.TrimSpace(token.SessionID) != "" &&
		(token.AssuranceLevel == "aal1" || token.AssuranceLevel == "aal2") &&
		len(token.AssuranceMethods) > 0 && !token.AuthenticationAt.IsZero() &&
		!token.IssuedAt.IsZero() && !token.IssuedAt.After(now.Add(time.Minute)) &&
		token.IssuedAt.Before(token.ExpiresAt) &&
		!token.ExpiresAt.IsZero() && now.Before(token.ExpiresAt) &&
		audiencesAllowed(token.Audiences, s.client.config.AccessTokenAudience)
}

func (s *SessionClient) validIDContext(token auth.ValidatedTokenContext) bool {
	now := s.clock()
	return strings.TrimRight(token.Issuer, "/") == s.client.config.Issuer &&
		(token.ClientID == "" || token.ClientID == s.client.config.ClientID) &&
		!token.IssuedAt.IsZero() && !token.IssuedAt.After(now.Add(time.Minute)) &&
		token.IssuedAt.Before(token.ExpiresAt) &&
		!token.ExpiresAt.IsZero() && now.Before(token.ExpiresAt) &&
		audiencesAllowed(token.Audiences, s.client.config.IDTokenAudience)
}

func audiencesAllowed(values, expected []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		allowed := slices.Contains(expected, value)
		if !allowed {
			return false
		}
	}
	return true
}

func (s *SessionClient) RevokeProviderSession(ctx context.Context, request auth.ProviderRevocationRequest) (auth.ProviderRemoteRevocationOutcome, error) {
	if !s.validRevocationRequest(request) {
		return auth.ProviderRemoteRevocationOutcome{
			Status:                auth.ProviderRemoteRevocationFailed,
			ResidualAccessExpires: request.Tokens.AccessExpiresAt(),
		}, auth.ErrProviderOperationUnauthorized
	}
	return s.SignOut(ctx, request.Tokens, SignOutCurrent)
}

func (s *SessionClient) validRevocationToken(tokens auth.ProviderTokenSet) bool {
	context, ok := tokens.AccessContext()
	return ok &&
		strings.TrimSpace(context.Subject) != "" &&
		s.validAccessContext(context)
}

func (s *SessionClient) validRevocationRequest(request auth.ProviderRevocationRequest) bool {
	if s == nil || s.client == nil ||
		strings.TrimSpace(request.Session.ID) == "" ||
		request.Session.Binding.Validate() != nil ||
		request.Session.Binding.Provider != ProviderKey ||
		request.Session.Binding.Environment != s.client.config.Environment ||
		strings.TrimRight(request.Session.Binding.Issuer, "/") != s.client.config.Issuer ||
		request.Session.Binding.ClientID != s.client.config.ClientID {
		return false
	}
	context, ok := request.Tokens.AccessContext()
	if !ok || !s.validAccessContext(context) ||
		context.Subject != request.Session.Principal.ProviderSubject ||
		strings.TrimSpace(request.Session.Principal.Provider) != ProviderKey ||
		strings.TrimSpace(request.Session.Principal.ProviderSubject) == "" {
		return false
	}
	sessionID := strings.TrimSpace(request.Session.Principal.ProviderSessionID)
	return sessionID != "" && context.SessionID == sessionID
}

type refreshResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}

func refreshTokenContext(claims jwt.MapClaims) (auth.ValidatedTokenContext, error) {
	if claims == nil {
		return auth.ValidatedTokenContext{}, errors.New("missing claims")
	}
	subject, _ := claims["sub"].(string)
	issuer, _ := claims["iss"].(string)
	if strings.TrimSpace(subject) == "" || strings.TrimSpace(issuer) == "" {
		return auth.ValidatedTokenContext{}, errors.New("missing subject or issuer")
	}
	audiences, err := claims.GetAudience()
	if err != nil {
		return auth.ValidatedTokenContext{}, err
	}
	issuedAt, err := claims.GetIssuedAt()
	if err != nil || issuedAt == nil {
		return auth.ValidatedTokenContext{}, errors.New("missing issued-at")
	}
	expiresAt, err := claims.GetExpirationTime()
	if err != nil || expiresAt == nil {
		return auth.ValidatedTokenContext{}, errors.New("missing expiry")
	}
	return auth.ValidatedTokenContext{
		Issuer:            issuer,
		Subject:           subject,
		Audiences:         audiences,
		SessionID:         claimString(claims, "session_id", "sid"),
		ClientID:          claimString(claims, "client_id", "azp"),
		AssuranceLevel:    claimString(claims, "aal", "acr"),
		AssuranceMethods:  claimStrings(claims["amr"]),
		AuthenticationAt:  claimTime(claims["auth_time"]),
		IssuedAt:          issuedAt.Time,
		ExpiresAt:         expiresAt.Time,
		TokenID:           claimString(claims, "jti"),
		TenantID:          claimString(claims, "tenant_id"),
		OrganizationID:    claimString(claims, "organization_id", "org_id"),
		PermissionVersion: claimString(claims, "permission_version", "permissions_version"),
	}, nil
}

func claimString(claims jwt.MapClaims, names ...string) string {
	for _, name := range names {
		if value, _ := claims[name].(string); strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func claimStrings(raw any) []string {
	switch values := raw.(type) {
	case []string:
		return compact(values)
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok {
				out = append(out, text)
			}
		}
		return compact(out)
	default:
		return nil
	}
}

func claimTime(raw any) time.Time {
	switch value := raw.(type) {
	case float64:
		return time.Unix(int64(value), 0).UTC()
	case int64:
		return time.Unix(value, 0).UTC()
	case json.Number:
		parsed, _ := strconv.ParseInt(value.String(), 10, 64)
		return time.Unix(parsed, 0).UTC()
	default:
		return time.Time{}
	}
}

var (
	_ auth.ProviderTokenRefresher  = (*SessionClient)(nil)
	_ auth.ProviderTokenReconciler = (*SessionClient)(nil)
	_ auth.ProviderRevocationHook  = (*SessionClient)(nil)
)
