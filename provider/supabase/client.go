package supabase

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	auth "github.com/goliatone/go-auth"
)

const maxRequestBodyBytes = 64 << 10

type RetryPolicy struct {
	MaxAttempts int
	MinBackoff  time.Duration
	MaxBackoff  time.Duration
}

func (p RetryPolicy) normalized() RetryPolicy {
	if p.MaxAttempts == 0 {
		p.MaxAttempts = 3
	}
	if p.MinBackoff == 0 {
		p.MinBackoff = 10 * time.Millisecond
	}
	if p.MaxBackoff == 0 {
		p.MaxBackoff = 250 * time.Millisecond
	}
	if p.MaxAttempts < 1 {
		p.MaxAttempts = 1
	}
	if p.MaxAttempts > 3 {
		p.MaxAttempts = 3
	}
	if p.MinBackoff < 0 {
		p.MinBackoff = 0
	}
	if p.MaxBackoff < p.MinBackoff {
		p.MaxBackoff = p.MinBackoff
	}
	if p.MaxBackoff > 2*time.Second {
		p.MaxBackoff = 2 * time.Second
	}
	return p
}

type Client struct {
	config            Config
	httpClient        *http.Client
	userTokens        auth.UserTokenProvider
	activitySink      auth.ActivitySink
	auditErrorHandler func(context.Context, error)
	retry             RetryPolicy
}

type ClientOption func(*Client)

func WithRetryPolicy(policy RetryPolicy) ClientOption {
	return func(client *Client) {
		if client != nil {
			client.retry = policy.normalized()
		}
	}
}

// WithActivitySink records one best-effort audit event for every validated
// provider lifecycle operation. Persistence and retry remain host-owned.
func WithActivitySink(sink auth.ActivitySink) ClientOption {
	return func(client *Client) {
		if client != nil {
			client.activitySink = sink
		}
	}
}

// WithActivityErrorHandler makes best-effort audit delivery failures visible
// without changing an already-completed provider operation's result.
func WithActivityErrorHandler(handler func(context.Context, error)) ClientOption {
	return func(client *Client) {
		if client != nil {
			client.auditErrorHandler = handler
		}
	}
}

func NewClient(config Config, userTokens auth.UserTokenProvider, httpClient *http.Client, options ...ClientOption) (*Client, error) {
	config = config.WithDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	cloned := *httpClient
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client := &Client{
		config:     config,
		httpClient: &cloned,
		userTokens: userTokens,
		retry:      (RetryPolicy{}).normalized(),
	}
	for _, option := range options {
		if option != nil {
			option(client)
		}
	}
	return client, nil
}

type credentialMode uint8

const (
	adminCredential credentialMode = iota + 1
	userCredential
	publishableCredential
)

type requestOptions struct {
	Method         string
	Path           string
	Body           any
	RequestID      string
	IdempotencyKey string
	RetrySafe      bool
	Credential     credentialMode
	UserSession    *auth.ProviderUserSession
	ExpectedUser   string
}

type responseEnvelope struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (c *Client) adminJSON(ctx context.Context, options requestOptions, output any) (responseEnvelope, error) {
	options.Credential = adminCredential
	return c.doJSON(ctx, options, output)
}

func (c *Client) userJSON(ctx context.Context, options requestOptions, output any) (responseEnvelope, error) {
	options.Credential = userCredential
	return c.doJSON(ctx, options, output)
}

func (c *Client) publishableJSON(ctx context.Context, options requestOptions, output any) (responseEnvelope, error) {
	options.Credential = publishableCredential
	return c.doJSON(ctx, options, output)
}

//nolint:gocyclo,funlen // Credential boundaries, mutation ambiguity, and retry policy remain explicit.
func (c *Client) doJSON(ctx context.Context, options requestOptions, output any) (responseEnvelope, error) {
	if c == nil {
		return responseEnvelope{}, ErrProviderUnavailable
	}
	endpoint, err := c.resolvePath(options.Path)
	if err != nil {
		return responseEnvelope{}, err
	}
	method := strings.ToUpper(strings.TrimSpace(options.Method))
	if method == "" {
		method = http.MethodGet
	}
	body, err := encodeRequestBody(options.Body)
	if err != nil {
		return responseEnvelope{}, err
	}
	if !safeHeaderValue(options.RequestID) || !safeHeaderValue(options.IdempotencyKey) {
		return responseEnvelope{}, fmt.Errorf("%w: request metadata is invalid", auth.ErrProviderOperationInvalid)
	}
	if options.RetrySafe && mutationMethod(method) && strings.TrimSpace(options.IdempotencyKey) == "" {
		return responseEnvelope{}, fmt.Errorf("%w: retryable mutation requires an idempotency key", auth.ErrProviderOperationInvalid)
	}
	if !options.RetrySafe && c.retry.MaxAttempts > 1 {
		// Unsafe mutations are deliberately attempted once.
		options.RetrySafe = false
	}

	var token auth.Secret
	switch options.Credential {
	case adminCredential:
		token = c.config.AdminCredential
	case publishableCredential:
		token = c.config.PublishableKey
	case userCredential:
		if options.UserSession == nil || c.userTokens == nil {
			return responseEnvelope{}, fmt.Errorf("%w: user token boundary is unavailable", auth.ErrProviderOperationUnauthorized)
		}
		now := time.Now().UTC()
		if sessionErr := options.UserSession.Validate(ProviderKey, c.config.Environment, now); sessionErr != nil {
			return responseEnvelope{}, sessionErr
		}
		if strings.TrimRight(strings.TrimSpace(options.UserSession.Binding.Issuer), "/") != c.config.Issuer ||
			strings.TrimSpace(options.UserSession.Binding.ClientID) != strings.TrimSpace(c.config.ClientID) {
			return responseEnvelope{}, fmt.Errorf("%w: provider project binding mismatch", auth.ErrProviderOperationUnauthorized)
		}
		if expected := strings.TrimSpace(options.ExpectedUser); expected == "" ||
			expected != options.UserSession.Principal.ProviderSubject() {
			return responseEnvelope{}, fmt.Errorf("%w: provider user mismatch", auth.ErrProviderOperationUnauthorized)
		}
		token, err = c.userTokens.AccessToken(ctx, auth.UserTokenRequest{
			SessionHandle: options.UserSession.SessionHandle,
			Binding:       options.UserSession.Binding,
			Target:        options.UserSession.TokenTarget,
			Capability:    options.UserSession.Capability,
		})
		if err != nil || token.IsZero() {
			return responseEnvelope{}, fmt.Errorf("%w: provider user token unavailable", auth.ErrProviderOperationUnauthorized)
		}
	default:
		return responseEnvelope{}, fmt.Errorf("%w: credential mode is invalid", auth.ErrProviderOperationUnauthorized)
	}

	attempts := 1
	if options.RetrySafe {
		attempts = c.retry.MaxAttempts
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		response, requestErr := c.doAttempt(ctx, endpoint, method, body, token, options)
		if requestErr == nil {
			return decodeResponseOutput(response, method, options, output)
		}
		lastErr = requestErr
		var providerErr *ProviderError
		if attempt == attempts || !errors.As(requestErr, &providerErr) || !providerErr.Retryable {
			return response, requestErr
		}
		if err := waitRetry(ctx, retryDelay(c.retry, attempt, providerErr, response.Header)); err != nil {
			return responseEnvelope{}, err
		}
	}
	return responseEnvelope{}, lastErr
}

func decodeResponseOutput(
	response responseEnvelope,
	method string,
	options requestOptions,
	output any,
) (responseEnvelope, error) {
	if output == nil || len(response.Body) == 0 {
		return response, nil
	}
	if err := json.Unmarshal(response.Body, output); err == nil {
		return response, nil
	}
	if unsafeMutation(method, options) {
		return response, ambiguousProviderError(
			firstNonEmpty(response.Header.Get("X-Request-ID"), options.RequestID),
			ErrProviderUnavailable,
		)
	}
	return responseEnvelope{}, &ProviderError{
		Kind: ErrorExternal, StatusCode: response.StatusCode,
		RequestID: response.Header.Get("X-Request-ID"), cause: ErrProviderUnavailable,
	}
}

func (c *Client) doAttempt(
	ctx context.Context,
	endpoint *url.URL,
	method string,
	body []byte,
	token auth.Secret,
	options requestOptions,
) (responseEnvelope, error) {
	requestCtx, cancel := context.WithTimeout(ctx, c.config.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return responseEnvelope{}, fmt.Errorf("%w: request construction failed", auth.ErrProviderOperationInvalid)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", strings.TrimSpace(options.RequestID))
	request.Header.Set("X-Supabase-Api-Version", c.config.AuthAPIVersion)
	request.Header.Set("X-Supabase-OAuth-Version", c.config.OAuthAPIVersion)
	request.Header.Set("Authorization", "Bearer "+token.Reveal())
	if options.Credential == userCredential || options.Credential == publishableCredential {
		request.Header.Set("apikey", c.config.PublishableKey.Reveal())
	} else {
		request.Header.Set("apikey", c.config.AdminCredential.Reveal())
	}
	if key := strings.TrimSpace(options.IdempotencyKey); key != "" {
		request.Header.Set("Idempotency-Key", key)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		if !options.RetrySafe {
			return responseEnvelope{}, ambiguousProviderError(options.RequestID, err)
		}
		return responseEnvelope{}, &ProviderError{
			Kind: ErrorExternal, RequestID: options.RequestID, Retryable: true, cause: ErrProviderUnavailable,
		}
	}
	defer func() {
		_ = response.Body.Close()
	}()

	payload, err := readBounded(response.Body, c.config.ResponseBodyBytes)
	if err != nil {
		if unsafeMutation(method, options) {
			return responseEnvelope{
					StatusCode: response.StatusCode,
					Header:     response.Header.Clone(),
				}, ambiguousProviderError(
					firstNonEmpty(response.Header.Get("X-Request-ID"), options.RequestID),
					err,
				)
		}
		return responseEnvelope{}, err
	}
	envelope := responseEnvelope{StatusCode: response.StatusCode, Header: response.Header.Clone(), Body: payload}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		code := responseCode(payload)
		mapped := providerError(response.StatusCode, code, firstNonEmpty(
			response.Header.Get("X-Request-ID"), options.RequestID,
		))
		if mutationMethod(method) && !options.RetrySafe {
			mapped.Retryable = false
			if response.StatusCode >= 500 && response.StatusCode != http.StatusNotImplemented {
				mapped.Kind = ErrorAmbiguous
				mapped.Ambiguous = true
				mapped.cause = errors.Join(ErrAmbiguousMutation, ErrProviderUnavailable)
			}
		}
		return envelope, mapped
	}
	return envelope, nil
}

func (c *Client) resolvePath(path string) (*url.URL, error) {
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "/auth/v1/") || strings.Contains(path, "\\") {
		return nil, fmt.Errorf("%w: provider path is not allowed", auth.ErrProviderOperationInvalid)
	}
	base, err := url.Parse(c.config.ProjectURL)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	reference, err := url.Parse(path)
	if err != nil || reference.IsAbs() || reference.Host != "" || reference.User != nil ||
		reference.Fragment != "" || reference.RawQuery != "" {
		return nil, fmt.Errorf("%w: provider path is invalid", auth.ErrProviderOperationInvalid)
	}
	for segment := range strings.SplitSeq(reference.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, fmt.Errorf("%w: provider path traversal is invalid", auth.ErrProviderOperationInvalid)
		}
	}
	resolved := base.ResolveReference(reference)
	if !strings.HasPrefix(resolved.Path, "/auth/v1/") {
		return nil, fmt.Errorf("%w: provider path escaped the allowed surface", auth.ErrProviderOperationInvalid)
	}
	return resolved, nil
}

func encodeRequestBody(value any) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	body, err := json.Marshal(value)
	if err != nil || len(body) > maxRequestBodyBytes {
		return nil, fmt.Errorf("%w: request body is invalid", auth.ErrProviderOperationInvalid)
	}
	return body, nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	if int64(len(payload)) > limit {
		return nil, ErrResponseTooLarge
	}
	return payload, nil
}

func responseCode(payload []byte) string {
	var body struct {
		Code      string `json:"code"`
		ErrorCode string `json:"error_code"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &body) != nil {
		return ""
	}
	return safeErrorCode(firstNonEmpty(body.Code, body.ErrorCode))
}

func retryDelay(policy RetryPolicy, attempt int, providerErr *ProviderError, header http.Header) time.Duration {
	delay := policy.MinBackoff << (attempt - 1)
	if raw := strings.TrimSpace(header.Get("Retry-After")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 0 {
			delay = time.Duration(seconds) * time.Second
		}
	}
	if delay > policy.MaxBackoff {
		delay = policy.MaxBackoff
	}
	if delay < 0 {
		return 0
	}
	return delay
}

func waitRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func safeHeaderValue(value string) bool {
	if len(value) > 1024 {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func mutationMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func unsafeMutation(method string, options requestOptions) bool {
	return mutationMethod(method) && !options.RetrySafe
}
