package supabase

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	"github.com/stretchr/testify/require"
)

type tokenProviderStub struct {
	token auth.Secret
	calls atomic.Int32
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type failingReadCloser struct{}

func (failingReadCloser) Read([]byte) (int, error) { return 0, errors.New("response stream failed") }
func (failingReadCloser) Close() error             { return nil }

func (s *tokenProviderStub) AccessToken(context.Context, auth.UserTokenRequest) (auth.Secret, error) {
	s.calls.Add(1)
	return s.token, nil
}

func testConfig(projectURL string) Config {
	return Config{
		ProjectURL:              projectURL,
		ClientID:                "client-1",
		ClientSecret:            auth.NewSecret("client-secret"),
		TokenEndpointAuthMethod: oidc.TokenEndpointAuthClientSecretBasic,
		CallbackURL:             projectURL + "/callback",
		IDTokenAudience:         []string{"client-1"},
		AccessTokenAudience:     []string{"authenticated"},
		AuthorizationUIURL:      projectURL + "/oauth/authorize",
		AllowedReturnURLs:       []string{projectURL + "/client/callback"},
		AdminCredential:         auth.NewSecret("admin-secret"),
		PublishableKey:          auth.NewSecret("publishable-key"),
		ManagementCredential:    auth.NewSecret("management-secret"),
		Environment:             "test",
		AllowInsecureLoopback:   true,
		RequestTimeout:          time.Second,
		ResponseBodyBytes:       1024,
	}.WithDefaults()
}

func testProviderUserSession(t *testing.T, expiresAt time.Time) auth.ProviderUserSession {
	t.Helper()
	capability, err := auth.NewTokenTargetCapability()
	require.NoError(t, err)
	principal, err := auth.NewAuthenticatedPrincipal(auth.AuthenticatedPrincipalInput{
		ApplicationSubject: "app-user-1",
		Provider:           ProviderKey,
		ProviderSubject:    "5f090ad0-09fb-49e0-884d-a4453d1a7c33",
		ProviderSessionID:  "provider-session-1",
		ClientID:           "client-1",
		ExpiresAt:          expiresAt,
	})
	require.NoError(t, err)
	return auth.ProviderUserSession{
		SessionHandle: auth.NewSecret("opaque-handle"),
		Binding: auth.ProviderSessionBinding{
			Host:          "backoffice.example",
			ApplicationID: "backoffice",
			Environment:   "test",
			Provider:      ProviderKey,
			Issuer:        "http://127.0.0.1/auth/v1",
			ClientID:      "client-1",
		},
		Principal:   principal,
		TokenTarget: "supabase-authorization",
		Capability:  capability,
	}
}

func TestClientSeparatesAdminAndUserCredentials(t *testing.T) {
	type seenHeaders struct {
		authorization string
		apiKey        string
		requestID     string
	}
	seen := make(chan seenHeaders, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- seenHeaders{
			authorization: r.Header.Get("Authorization"),
			apiKey:        r.Header.Get("apikey"),
			requestID:     r.Header.Get("X-Request-ID"),
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	tokens := &tokenProviderStub{token: auth.NewSecret("current-user-token")}
	client, err := NewClient(testConfig(server.URL), tokens, server.Client())
	require.NoError(t, err)
	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodGet, Path: "/auth/v1/admin/users/id", RequestID: "admin-request", RetrySafe: true,
	}, nil)
	require.NoError(t, err)
	session := testProviderUserSession(t, time.Now().Add(time.Hour))
	session.Binding.Issuer = strings.TrimRight(server.URL, "/") + "/auth/v1"
	_, err = client.userJSON(context.Background(), requestOptions{
		Method: http.MethodGet, Path: "/auth/v1/oauth/authorizations/id", RequestID: "user-request",
		RetrySafe: true, UserSession: &session, ExpectedUser: session.Principal.ProviderSubject(),
	}, nil)
	require.NoError(t, err)

	admin := <-seen
	user := <-seen
	require.Equal(t, "Bearer admin-secret", admin.authorization)
	require.Equal(t, "admin-secret", admin.apiKey)
	require.Equal(t, "admin-request", admin.requestID)
	require.Equal(t, "Bearer current-user-token", user.authorization)
	require.Equal(t, "publishable-key", user.apiKey)
	require.Equal(t, int32(1), tokens.calls.Load())
	for _, header := range []seenHeaders{admin, user} {
		require.NotContains(t, header.authorization, "management-secret")
	}
}

func TestClientRejectsInvalidUserSessionBeforeTransport(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), &tokenProviderStub{token: auth.NewSecret("user-token")}, server.Client())
	require.NoError(t, err)
	session := testProviderUserSession(t, time.Now().Add(-time.Minute))
	session.Binding.Issuer = strings.TrimRight(server.URL, "/") + "/auth/v1"
	_, err = client.userJSON(context.Background(), requestOptions{
		Method: http.MethodGet, Path: "/auth/v1/oauth/authorizations/id",
		RetrySafe: true, UserSession: &session,
	}, nil)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)
	require.Zero(t, calls.Load())
}

func TestClientRejectsProjectMismatchWrongUserAndPathTraversal(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), &tokenProviderStub{token: auth.NewSecret("user-token")}, server.Client())
	require.NoError(t, err)
	session := testProviderUserSession(t, time.Now().Add(time.Hour))

	_, err = client.userJSON(context.Background(), requestOptions{
		Method: http.MethodGet, Path: "/auth/v1/oauth/authorizations/id", RetrySafe: true,
		UserSession: &session, ExpectedUser: session.Principal.ProviderSubject(),
	}, nil)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)

	session.Binding.Issuer = strings.TrimRight(server.URL, "/") + "/auth/v1"
	_, err = client.userJSON(context.Background(), requestOptions{
		Method: http.MethodGet, Path: "/auth/v1/oauth/authorizations/id", RetrySafe: true,
		UserSession: &session, ExpectedUser: "different-user",
	}, nil)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)

	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodGet, Path: "/auth/v1/../admin/users",
	}, nil)
	require.ErrorIs(t, err, auth.ErrProviderOperationInvalid)
	require.Zero(t, calls.Load())
}

func TestClientBoundsRetriesAndNeverReplaysUnsafeMutation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := calls.Add(1)
		if count < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"message":"do not expose this body"}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client(), WithRetryPolicy(RetryPolicy{
		MaxAttempts: 3, MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond,
	}))
	require.NoError(t, err)
	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodGet, Path: "/auth/v1/admin/users/id", RetrySafe: true,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, int32(3), calls.Load())

	calls.Store(0)
	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodPost, Path: "/auth/v1/admin/users/id", Body: map[string]any{"ban": true},
		RetrySafe: false,
	}, nil)
	require.Error(t, err)
	require.Equal(t, int32(1), calls.Load())
}

func TestClientRequiresIdempotencyKeyBeforeRetryingMutation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("transport must not be called")
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodPost, Path: "/auth/v1/admin/users/id", RetrySafe: true,
	}, nil)
	require.ErrorIs(t, err, auth.ErrProviderOperationInvalid)
}

func TestClientRejectsRedirectsAndOversizedBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "redirect") {
			http.Redirect(w, r, "/auth/v1/admin/final", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, strings.Repeat("x", 2048))
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodGet, Path: "/auth/v1/admin/redirect",
	}, nil)
	require.Error(t, err)
	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodGet, Path: "/auth/v1/admin/large",
	}, nil)
	require.ErrorIs(t, err, ErrResponseTooLarge)
}

func TestProviderErrorsNeverIncludeSensitiveResponseBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Request-ID", "provider-request")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"access_token=top-secret","code":"invalid_token"}`)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodGet, Path: "/auth/v1/admin/users/id",
	}, nil)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)
	require.NotContains(t, err.Error(), "top-secret")
	require.NotContains(t, err.Error(), "access_token")
	var providerErr *ProviderError
	require.True(t, errors.As(err, &providerErr))
	require.Equal(t, "invalid_token", providerErr.Code)
	require.Equal(t, "provider-request", providerErr.RequestID)
}

func TestClientMapsConflictRateLimitAndMalformedSuccess(t *testing.T) {
	status := atomic.Int32{}
	status.Store(http.StatusConflict)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
		if status.Load() == http.StatusOK {
			_, _ = io.WriteString(w, `not-json`)
			return
		}
		_, _ = io.WriteString(w, `{"code":"already_exists"}`)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)

	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodPost, Path: "/auth/v1/admin/users/id",
	}, nil)
	require.ErrorIs(t, err, auth.ErrProviderOperationConflict)

	status.Store(http.StatusTooManyRequests)
	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodPost, Path: "/auth/v1/admin/users/id",
	}, nil)
	require.ErrorIs(t, err, ErrRateLimited)

	status.Store(http.StatusOK)
	var output map[string]any
	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodGet, Path: "/auth/v1/admin/users/id",
	}, &output)
	require.ErrorIs(t, err, ErrProviderUnavailable)
}

func TestClientTreatsUnsafeTimeoutAsAmbiguousAndDoesNotRetry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(30 * time.Millisecond)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	cfg := testConfig(server.URL)
	cfg.RequestTimeout = 5 * time.Millisecond
	client, err := NewClient(cfg, nil, server.Client(), WithRetryPolicy(RetryPolicy{
		MaxAttempts: 3, MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond,
	}))
	require.NoError(t, err)
	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodPost, Path: "/auth/v1/admin/users/id", Body: map[string]bool{"ban": true},
	}, nil)
	require.ErrorIs(t, err, ErrAmbiguousMutation)
	require.Equal(t, int32(1), calls.Load())
}

func TestClientTreatsUnsafeServerFailureAsAmbiguous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodPost, Path: "/auth/v1/admin/users/id",
	}, nil)
	require.ErrorIs(t, err, ErrAmbiguousMutation)
	var providerErr *ProviderError
	require.True(t, errors.As(err, &providerErr))
	require.True(t, providerErr.Ambiguous)
	require.False(t, providerErr.Retryable)
}

func TestClientTreatsUnreadableUnsafeMutationSuccessAsAmbiguous(t *testing.T) {
	t.Parallel()

	tests := map[string]func() io.ReadCloser{
		"malformed json": func() io.ReadCloser {
			return io.NopCloser(strings.NewReader("not-json"))
		},
		"oversized body": func() io.ReadCloser {
			return io.NopCloser(strings.NewReader(strings.Repeat("x", 2048)))
		},
		"truncated body": func() io.ReadCloser {
			return failingReadCloser{}
		},
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32
			httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"X-Request-Id": []string{"provider-request"}},
					Body:       body(),
				}, nil
			})}
			client, err := NewClient(testConfig("http://127.0.0.1:54321"), nil, httpClient)
			require.NoError(t, err)

			var output map[string]any
			envelope, err := client.adminJSON(context.Background(), requestOptions{
				Method: http.MethodPost, Path: "/auth/v1/admin/users/id",
				RequestID: "host-request",
			}, &output)

			require.ErrorIs(t, err, ErrAmbiguousMutation)
			require.Equal(t, int32(1), calls.Load())
			require.Equal(t, "provider-request", envelope.Header.Get("X-Request-ID"))
			var providerErr *ProviderError
			require.ErrorAs(t, err, &providerErr)
			require.True(t, providerErr.Ambiguous)
			require.False(t, providerErr.Retryable)
		})
	}
}

func TestClientRejectsControlCharactersInRequestMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("transport must not be called")
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	_, err = client.adminJSON(context.Background(), requestOptions{
		Method: http.MethodGet, Path: "/auth/v1/admin/users/id", RequestID: "request\r\nInjected: true",
	}, nil)
	require.ErrorIs(t, err, auth.ErrProviderOperationInvalid)
}
