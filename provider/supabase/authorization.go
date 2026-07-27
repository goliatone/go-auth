package supabase

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	auth "github.com/goliatone/go-auth"
)

const DefaultAuthorizationTTL = 15 * time.Minute

type AuthorizationClientPolicy struct {
	Name          string
	RedirectURLs  []string
	AllowedScopes []string
}

type AuthorizationCSRFContext struct {
	AuthorizationID   string
	Binding           string
	Action            auth.ProviderOperationAction
	ClientID          string
	RequestedScopes   []string
	GrantedScopes     []string
	ProviderSubject   string
	ProviderSessionID string
	Environment       string
	DetailsExpiresAt  time.Time
}

type AuthorizationCSRFVerifier interface {
	VerifyAuthorizationCSRF(context.Context, AuthorizationCSRFContext) error
}

type AuthorizationCSRFVerifierFunc func(context.Context, AuthorizationCSRFContext) error

func (f AuthorizationCSRFVerifierFunc) VerifyAuthorizationCSRF(ctx context.Context, csrf AuthorizationCSRFContext) error {
	if f == nil {
		return auth.ErrProviderOperationUnauthorized
	}
	csrf.RequestedScopes = slices.Clone(csrf.RequestedScopes)
	csrf.GrantedScopes = slices.Clone(csrf.GrantedScopes)
	return f(ctx, csrf)
}

type AuthorizationServiceConfig struct {
	Client           *Client
	Clients          map[string]AuthorizationClientPolicy
	CSRFVerifier     AuthorizationCSRFVerifier
	DecisionProofKey auth.Secret
	MaxTTL           time.Duration
	Clock            func() time.Time
}

type AuthorizationService struct {
	client       *Client
	clients      map[string]AuthorizationClientPolicy
	csrfVerifier AuthorizationCSRFVerifier
	proofKey     auth.Secret
	maxTTL       time.Duration
	clock        func() time.Time
}

//nolint:gocyclo // Client policy and proof configuration invariants are validated explicitly.
func NewAuthorizationService(config AuthorizationServiceConfig) (*AuthorizationService, error) {
	if config.Client == nil || config.CSRFVerifier == nil || len(config.Clients) == 0 ||
		len(config.DecisionProofKey.Reveal()) < 32 || len(config.DecisionProofKey.Reveal()) > 128 ||
		sameSecret(config.DecisionProofKey, config.Client.config.ClientSecret) ||
		sameSecret(config.DecisionProofKey, config.Client.config.AdminCredential) ||
		sameSecret(config.DecisionProofKey, config.Client.config.PublishableKey) ||
		sameSecret(config.DecisionProofKey, config.Client.config.ManagementCredential) {
		return nil, ErrInvalidConfig
	}
	if config.MaxTTL == 0 {
		config.MaxTTL = DefaultAuthorizationTTL
	}
	if config.MaxTTL <= 0 || config.MaxTTL > time.Hour {
		return nil, ErrInvalidConfig
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	clients := make(map[string]AuthorizationClientPolicy, len(config.Clients))
	for clientID, policy := range config.Clients {
		clientID = strings.TrimSpace(clientID)
		policy.Name = strings.TrimSpace(policy.Name)
		redirectURLs := compact(policy.RedirectURLs)
		allowedScopes := compact(policy.AllowedScopes)
		if clientID == "" || policy.Name == "" ||
			len(redirectURLs) == 0 || len(redirectURLs) != len(policy.RedirectURLs) ||
			len(allowedScopes) == 0 || len(allowedScopes) != len(policy.AllowedScopes) {
			return nil, ErrInvalidConfig
		}
		if _, exists := clients[clientID]; exists {
			return nil, ErrInvalidConfig
		}
		policy.RedirectURLs = redirectURLs
		policy.AllowedScopes = allowedScopes
		for _, redirect := range redirectURLs {
			if _, err := validateEndpoint(redirect, config.Client.config.AllowInsecureLoopback, true); err != nil {
				return nil, ErrInvalidConfig
			}
		}
		clients[clientID] = policy
	}
	return &AuthorizationService{
		client: config.Client, clients: clients, csrfVerifier: config.CSRFVerifier,
		proofKey: config.DecisionProofKey, maxTTL: config.MaxTTL, clock: config.Clock,
	}, nil
}

var authorizationIDPattern = regexp.MustCompile(`\A[A-Za-z0-9_-]{8,512}\z`)

//nolint:gocyclo // Provider response and redirect constraints remain explicit and fail closed.
func (s *AuthorizationService) GetAuthorizationDetails(
	ctx context.Context,
	request auth.AuthorizationDetailsRequest,
) (result auth.AuthorizationDetails, err error) {
	auditOutcome := auth.ProviderOperationOutcome{}
	defer func() {
		if err == nil {
			auditOutcome.Status = auth.ProviderOperationSucceeded
		}
		s.recordLifecycleActivity(ctx, request.Operation, auditOutcome, err)
	}()
	now := s.clock()
	if validationErr := request.Validate(ProviderKey, s.client.config.Environment, now); validationErr != nil ||
		!authorizationIDPattern.MatchString(request.Continuation.AuthorizationID) {
		return auth.AuthorizationDetails{}, auth.ErrProviderOperationUnauthorized
	}
	var response authorizationDetailsResponse
	_, err = s.client.userJSON(ctx, requestOptions{
		Method:       http.MethodGet,
		Path:         "/auth/v1/oauth/authorizations/" + url.PathEscape(request.Continuation.AuthorizationID),
		RequestID:    request.Operation.RequestID,
		RetrySafe:    true,
		UserSession:  &request.Session,
		ExpectedUser: request.Session.Principal.ProviderSubject(),
	}, &response)
	if err != nil {
		if errors.Is(err, auth.ErrProviderOperationInvalid) ||
			errors.Is(err, auth.ErrProviderOperationUnauthorized) ||
			errors.Is(err, auth.ErrProviderOperationConflict) {
			return auth.AuthorizationDetails{}, auth.ErrProviderOperationUnauthorized
		}
		return auth.AuthorizationDetails{}, err
	}
	policy, ok := s.clients[strings.TrimSpace(response.ClientID)]
	if !ok ||
		response.AuthorizationID != request.Continuation.AuthorizationID ||
		response.ExpiresAt.IsZero() || !now.Before(response.ExpiresAt) ||
		response.ExpiresAt.After(now.Add(s.maxTTL)) ||
		!slices.Contains(policy.RedirectURLs, strings.TrimSpace(response.RedirectURI)) ||
		!allowedScopes(response.Scopes, policy.AllowedScopes) {
		return auth.AuthorizationDetails{}, auth.ErrProviderOperationUnauthorized
	}
	details := auth.AuthorizationDetails{
		AuthorizationID: response.AuthorizationID,
		ClientID:        response.ClientID,
		ClientName:      policy.Name,
		Scopes:          compact(response.Scopes),
		RedirectURL:     response.RedirectURI,
		ExpiresAt:       response.ExpiresAt,
	}
	proof, err := s.issueAuthorizationDecisionProof(details, request.Session, now)
	if err != nil {
		return auth.AuthorizationDetails{}, ErrProviderUnavailable
	}
	details.DecisionProof = proof
	return details, nil
}

func (s *AuthorizationService) ApproveAuthorization(
	ctx context.Context,
	request auth.AuthorizationDecisionRequest,
) (auth.AuthorizationDecisionResult, error) {
	return s.decide(ctx, request, auth.ProviderActionAuthorizationApprove)
}

func (s *AuthorizationService) DenyAuthorization(
	ctx context.Context,
	request auth.AuthorizationDecisionRequest,
) (auth.AuthorizationDecisionResult, error) {
	return s.decide(ctx, request, auth.ProviderActionAuthorizationDeny)
}

//nolint:gocyclo // Authorization decision proof, CSRF, scope, and redirect gates stay sequential.
func (s *AuthorizationService) decide(
	ctx context.Context,
	request auth.AuthorizationDecisionRequest,
	action auth.ProviderOperationAction,
) (result auth.AuthorizationDecisionResult, err error) {
	defer func() {
		s.recordLifecycleActivity(ctx, request.Operation, result.ProviderOperationOutcome, err)
	}()
	now := s.clock()
	if validationErr := request.Validate(action, ProviderKey, s.client.config.Environment, now); validationErr != nil ||
		!authorizationIDPattern.MatchString(request.AuthorizationID) {
		return auth.AuthorizationDecisionResult{}, auth.ErrProviderOperationUnauthorized
	}
	proof, err := s.verifyAuthorizationDecisionProof(request, now)
	if err != nil {
		return auth.AuthorizationDecisionResult{}, auth.ErrProviderOperationUnauthorized
	}
	if action == auth.ProviderActionAuthorizationDeny && len(request.Scopes) != 0 {
		return auth.AuthorizationDecisionResult{}, auth.ErrProviderOperationInvalid
	}
	if action == auth.ProviderActionAuthorizationApprove && len(request.Scopes) == 0 {
		return auth.AuthorizationDecisionResult{}, auth.ErrProviderOperationInvalid
	}
	policy, ok := s.clients[request.ClientID]
	if !ok ||
		!allowedScopes(proof.Scopes, policy.AllowedScopes) ||
		(action == auth.ProviderActionAuthorizationApprove &&
			(!allowedScopes(request.Scopes, policy.AllowedScopes) ||
				!allowedScopes(request.Scopes, proof.Scopes))) {
		return auth.AuthorizationDecisionResult{}, auth.ErrProviderOperationUnauthorized
	}
	if csrfErr := s.csrfVerifier.VerifyAuthorizationCSRF(ctx, AuthorizationCSRFContext{
		AuthorizationID:   request.AuthorizationID,
		Binding:           request.CSRFBinding,
		Action:            action,
		ClientID:          request.ClientID,
		RequestedScopes:   proof.Scopes,
		GrantedScopes:     compact(request.Scopes),
		ProviderSubject:   request.Session.Principal.ProviderSubject(),
		ProviderSessionID: request.Session.Principal.ProviderSessionID(),
		Environment:       s.client.config.Environment,
		DetailsExpiresAt:  time.Unix(proof.ExpiresAt, 0).UTC(),
	}); csrfErr != nil {
		return auth.AuthorizationDecisionResult{}, auth.ErrProviderOperationUnauthorized
	}
	var response authorizationDecisionResponse
	envelope, err := s.client.userJSON(ctx, requestOptions{
		Method: http.MethodPost,
		Path:   "/auth/v1/oauth/authorizations/" + url.PathEscape(request.AuthorizationID) + "/consent",
		Body: map[string]any{
			"action": strings.TrimPrefix(string(action), "authorization."),
			"scopes": compact(request.Scopes),
		},
		RequestID:      request.Operation.RequestID,
		IdempotencyKey: request.Operation.OperationID,
		RetrySafe:      false,
		UserSession:    &request.Session,
		ExpectedUser:   request.Session.Principal.ProviderSubject(),
	}, &response)
	if err != nil {
		status := auth.ProviderOperationFailed
		if errors.Is(err, auth.ErrProviderOperationConflict) {
			status = auth.ProviderOperationConflict
		}
		if errors.Is(err, ErrAmbiguousMutation) {
			status, err = auth.ProviderOperationPending, auth.ErrProviderOperationPending
		}
		return auth.AuthorizationDecisionResult{
			ProviderOperationOutcome: auth.ProviderOperationOutcome{
				Status: status, ProviderRequestID: responseRequestID(envelope, request.Operation.RequestID),
			},
		}, err
	}
	if strings.TrimSpace(response.ClientID) != request.ClientID {
		return auth.AuthorizationDecisionResult{}, auth.ErrProviderOperationUnauthorized
	}
	if (action == auth.ProviderActionAuthorizationApprove && !allowedScopes(request.Scopes, policy.AllowedScopes)) ||
		validateAuthorizationRedirect(response.RedirectURI, policy.RedirectURLs, action) != nil {
		return auth.AuthorizationDecisionResult{}, auth.ErrProviderOperationUnauthorized
	}
	return auth.AuthorizationDecisionResult{
		ProviderOperationOutcome: auth.ProviderOperationOutcome{
			Status: auth.ProviderOperationSucceeded, ProviderRequestID: responseRequestID(envelope, request.Operation.RequestID),
		},
		RedirectURL: response.RedirectURI,
	}, nil
}

type authorizationDecisionProof struct {
	Version           int      `json:"v"`
	AuthorizationID   string   `json:"authorization_id"`
	ClientID          string   `json:"client_id"`
	Scopes            []string `json:"scopes"`
	ProviderSubject   string   `json:"provider_subject"`
	ProviderSessionID string   `json:"provider_session_id"`
	Environment       string   `json:"environment"`
	IssuedAt          int64    `json:"issued_at"`
	ExpiresAt         int64    `json:"expires_at"`
}

func (s *AuthorizationService) issueAuthorizationDecisionProof(
	details auth.AuthorizationDetails,
	session auth.ProviderUserSession,
	now time.Time,
) (auth.Secret, error) {
	payload := authorizationDecisionProof{
		Version:           1,
		AuthorizationID:   strings.TrimSpace(details.AuthorizationID),
		ClientID:          strings.TrimSpace(details.ClientID),
		Scopes:            canonicalScopes(details.Scopes),
		ProviderSubject:   session.Principal.ProviderSubject(),
		ProviderSessionID: session.Principal.ProviderSessionID(),
		Environment:       s.client.config.Environment,
		IssuedAt:          now.Unix(),
		ExpiresAt:         details.ExpiresAt.UTC().Unix(),
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > 4096 {
		return auth.Secret{}, ErrProviderUnavailable
	}
	body := base64.RawURLEncoding.EncodeToString(encoded)
	mac := hmac.New(sha256.New, []byte(s.proofKey.Reveal()))
	_, _ = mac.Write([]byte(body))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return auth.NewSecret(body + "." + signature), nil
}

//nolint:gocyclo // Every signed-proof binding is checked explicitly before authorization.
func (s *AuthorizationService) verifyAuthorizationDecisionProof(
	request auth.AuthorizationDecisionRequest,
	now time.Time,
) (authorizationDecisionProof, error) {
	raw := request.DecisionProof.Reveal()
	if len(raw) == 0 || len(raw) > 8192 {
		return authorizationDecisionProof{}, auth.ErrProviderOperationUnauthorized
	}
	body, signature, ok := strings.Cut(raw, ".")
	if !ok || body == "" || signature == "" || strings.Contains(signature, ".") {
		return authorizationDecisionProof{}, auth.ErrProviderOperationUnauthorized
	}
	provided, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return authorizationDecisionProof{}, auth.ErrProviderOperationUnauthorized
	}
	mac := hmac.New(sha256.New, []byte(s.proofKey.Reveal()))
	_, _ = mac.Write([]byte(body))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return authorizationDecisionProof{}, auth.ErrProviderOperationUnauthorized
	}
	encoded, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || len(encoded) > 4096 {
		return authorizationDecisionProof{}, auth.ErrProviderOperationUnauthorized
	}
	var proof authorizationDecisionProof
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return authorizationDecisionProof{}, auth.ErrProviderOperationUnauthorized
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return authorizationDecisionProof{}, auth.ErrProviderOperationUnauthorized
	}
	scopes := canonicalScopes(proof.Scopes)
	issuedAt := time.Unix(proof.IssuedAt, 0).UTC()
	expiresAt := time.Unix(proof.ExpiresAt, 0).UTC()
	if proof.Version != 1 ||
		proof.AuthorizationID != strings.TrimSpace(request.AuthorizationID) ||
		proof.ClientID != strings.TrimSpace(request.ClientID) ||
		proof.ProviderSubject != request.Session.Principal.ProviderSubject() ||
		proof.ProviderSessionID != request.Session.Principal.ProviderSessionID() ||
		proof.Environment != s.client.config.Environment ||
		len(scopes) == 0 || len(scopes) != len(proof.Scopes) ||
		issuedAt.After(now.Add(time.Minute)) ||
		!issuedAt.Before(expiresAt) ||
		!now.Before(expiresAt) ||
		expiresAt.After(issuedAt.Add(s.maxTTL)) {
		return authorizationDecisionProof{}, auth.ErrProviderOperationUnauthorized
	}
	proof.Scopes = scopes
	return proof, nil
}

func canonicalScopes(values []string) []string {
	values = compact(values)
	sort.Strings(values)
	return values
}

type authorizationDetailsResponse struct {
	AuthorizationID string    `json:"authorization_id"`
	ClientID        string    `json:"client_id"`
	ClientName      string    `json:"client_name"`
	Scopes          []string  `json:"scopes"`
	RedirectURI     string    `json:"redirect_uri"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type authorizationDecisionResponse struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
}

func allowedScopes(requested, allowed []string) bool {
	normalized := compact(requested)
	if len(normalized) == 0 || len(normalized) != len(requested) || len(normalized) > 32 {
		return false
	}
	for _, scope := range normalized {
		if !slices.Contains(allowed, scope) {
			return false
		}
	}
	return true
}

//nolint:gocyclo // Redirect normalization and allowlist checks are deliberately exhaustive.
func validateAuthorizationRedirect(raw string, allowed []string, action auth.ProviderOperationAction) error {
	if len(raw) == 0 || len(raw) > 4096 {
		return auth.ErrProviderOperationInvalid
	}
	redirect, err := url.Parse(raw)
	if err != nil || !redirect.IsAbs() || redirect.User != nil || redirect.Fragment != "" {
		return auth.ErrProviderOperationInvalid
	}
	var base *url.URL
	for _, candidate := range allowed {
		parsed, parseErr := url.Parse(candidate)
		if parseErr == nil &&
			parsed.Scheme == redirect.Scheme && parsed.Host == redirect.Host &&
			parsed.Path == redirect.Path && parsed.RawQuery == "" {
			base = parsed
			break
		}
	}
	if base == nil {
		return auth.ErrProviderOperationInvalid
	}
	query := redirect.Query()
	for key, values := range query {
		if !slices.Contains([]string{"code", "state", "error", "error_description", "error_uri"}, key) ||
			len(values) != 1 || len(values[0]) > 2048 {
			return auth.ErrProviderOperationInvalid
		}
	}
	if action == auth.ProviderActionAuthorizationApprove {
		if query.Get("code") == "" || query.Get("error") != "" {
			return auth.ErrProviderOperationInvalid
		}
	} else if query.Get("error") == "" || query.Get("code") != "" {
		return auth.ErrProviderOperationInvalid
	}
	return nil
}

var _ auth.AuthorizationDecisionService = (*AuthorizationService)(nil)
