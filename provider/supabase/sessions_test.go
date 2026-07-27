package supabase

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
	"github.com/stretchr/testify/require"
)

type refreshValidatorStub struct {
	idClaims     jwt.MapClaims
	accessClaims jwt.MapClaims
	err          error
}

func (s refreshValidatorStub) ValidateIDToken(context.Context, string, string) (jwt.MapClaims, error) {
	return s.idClaims, s.err
}

func (s refreshValidatorStub) ValidateIDTokenWithAccessToken(context.Context, string, string, string) (jwt.MapClaims, error) {
	return s.idClaims, s.err
}

func (s refreshValidatorStub) ValidateAccessToken(context.Context, string) (jwt.MapClaims, error) {
	return s.accessClaims, s.err
}

func refreshClaims(now time.Time, issuer string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":        issuer,
		"sub":        "5f090ad0-09fb-49e0-884d-a4453d1a7c33",
		"aud":        []string{"authenticated"},
		"session_id": "provider-session-1",
		"client_id":  "client-1",
		"role":       "authenticated",
		"aal":        "aal1",
		"amr":        []any{"password"},
		"auth_time":  float64(now.Add(-time.Minute).Unix()),
		"iat":        float64(now.Unix()),
		"exp":        float64(now.Add(time.Hour).Unix()),
	}
}

func providerRefreshRequest(t *testing.T, issuer string, now time.Time) auth.ProviderRefreshRequest {
	t.Helper()
	principal, err := auth.NewAuthenticatedPrincipal(auth.AuthenticatedPrincipalInput{
		ApplicationSubject: "app-user-1",
		Provider:           ProviderKey,
		ProviderSubject:    "5f090ad0-09fb-49e0-884d-a4453d1a7c33",
		ProviderSessionID:  "provider-session-1",
		ClientID:           "client-1",
	})
	require.NoError(t, err)
	current, err := auth.NewProviderTokenSet(auth.ProviderTokenSetInput{
		AccessToken:      auth.NewSecret("old-access"),
		RefreshToken:     auth.NewSecret("old-refresh"),
		IDToken:          auth.NewSecret("old-id"),
		TokenType:        "bearer",
		Scopes:           []string{"openid"},
		AcquiredAt:       now.Add(-time.Hour),
		AccessExpiresAt:  now,
		RefreshExpiresAt: now.Add(24 * time.Hour),
	})
	require.NoError(t, err)
	return auth.ProviderRefreshRequest{
		Session: auth.ProviderSession{
			ID:        "local-provider-session",
			Principal: auth.NewPrincipalSnapshot(principal),
			Binding: auth.ProviderSessionBinding{
				Host: "backoffice.example", ApplicationID: "backoffice", Environment: "test",
				Provider: ProviderKey, Issuer: issuer, ClientID: "client-1",
			},
		},
		AttemptID:     "attempt-1",
		RefreshToken:  auth.NewSecret("old-refresh"),
		CurrentTokens: current,
	}
}

func revocationTokenSet(
	t *testing.T,
	now time.Time,
	issuer, subject, sessionID string,
) auth.ProviderTokenSet {
	t.Helper()
	accessContext := auth.ValidatedTokenContext{
		Issuer:           issuer,
		Subject:          subject,
		Audiences:        []string{"authenticated"},
		SessionID:        sessionID,
		ClientID:         "client-1",
		AssuranceLevel:   "aal1",
		AssuranceMethods: []string{"password"},
		AuthenticationAt: now.Add(-time.Minute),
		IssuedAt:         now.Add(-time.Minute),
		ExpiresAt:        now.Add(time.Hour),
	}
	tokens, err := auth.NewProviderTokenSet(auth.ProviderTokenSetInput{
		AccessToken:     auth.NewSecret("current-access"),
		AccessExpiresAt: accessContext.ExpiresAt,
		AccessContext:   &accessContext,
	})
	require.NoError(t, err)
	return tokens
}

func TestSessionClientRefreshesAndValidatesRotatedTokens(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	var received url.Values
	var authorization string
	var grantType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		received = r.PostForm
		authorization = r.Header.Get("Authorization")
		grantType = r.URL.Query().Get("grant_type")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access", "refresh_token": "new-refresh",
			"id_token": "new-id", "token_type": "bearer", "expires_in": 3600,
			"refresh_expires_in": 7200, "scope": "openid profile",
		}))
	}))
	defer server.Close()
	cfg := testConfig(server.URL)
	client, err := NewClient(cfg, nil, server.Client())
	require.NoError(t, err)
	claims := refreshClaims(now, cfg.Issuer)
	idClaims := refreshClaims(now, cfg.Issuer)
	idClaims["aud"] = []string{"client-1"}
	sessionClient, err := NewSessionClient(client, refreshValidatorStub{idClaims: idClaims, accessClaims: claims})
	require.NoError(t, err)
	sessionClient.clock = func() time.Time { return now }

	result, err := sessionClient.RefreshProviderTokens(
		context.Background(), providerRefreshRequest(t, cfg.Issuer, now),
	)
	require.NoError(t, err)
	require.Equal(t, "new-access", result.Tokens.AccessToken().Reveal())
	require.Equal(t, "new-refresh", result.Tokens.RefreshToken().Reveal())
	require.Equal(t, "new-id", result.Tokens.IDToken().Reveal())
	require.Equal(t, []string{"openid", "profile"}, result.Tokens.Scopes())
	require.Equal(t, "refresh_token", grantType)
	require.Equal(t, "old-refresh", received.Get("refresh_token"))
	require.Equal(t, "client-1", received.Get("client_id"))
	require.True(t, strings.HasPrefix(authorization, "Basic "))
}

func TestSessionClientRejectsRefreshAndReportsAmbiguity(t *testing.T) {
	status := atomic.Int32{}
	status.Store(http.StatusUnauthorized)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	defer server.Close()
	cfg := testConfig(server.URL)
	client, err := NewClient(cfg, nil, server.Client())
	require.NoError(t, err)
	claims := refreshClaims(time.Now(), cfg.Issuer)
	sessionClient, err := NewSessionClient(client, refreshValidatorStub{idClaims: claims, accessClaims: claims})
	require.NoError(t, err)
	request := providerRefreshRequest(t, cfg.Issuer, time.Now())

	_, err = sessionClient.RefreshProviderTokens(context.Background(), request)
	require.ErrorIs(t, err, auth.ErrProviderRefreshRejected)
	status.Store(http.StatusServiceUnavailable)
	_, err = sessionClient.RefreshProviderTokens(context.Background(), request)
	require.ErrorIs(t, err, auth.ErrProviderRefreshAmbiguous)
}

func TestSessionClientRejectsRotatedTokenSubjectMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"new-access","refresh_token":"new-refresh","token_type":"bearer"}`)
	}))
	defer server.Close()
	cfg := testConfig(server.URL)
	client, err := NewClient(cfg, nil, server.Client())
	require.NoError(t, err)
	claims := refreshClaims(time.Now(), cfg.Issuer)
	claims["sub"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	sessionClient, err := NewSessionClient(client, refreshValidatorStub{accessClaims: claims})
	require.NoError(t, err)
	_, err = sessionClient.RefreshProviderTokens(
		context.Background(), providerRefreshRequest(t, cfg.Issuer, time.Now()),
	)
	require.ErrorIs(t, err, auth.ErrProviderRefreshRejected)
}

func TestSessionClientRejectsRotatedRoleAndScopeEscalation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		role  string
		scope string
	}{
		"service role":    {role: "service_role", scope: "openid"},
		"unknown scope":   {role: "authenticated", scope: "openid admin"},
		"duplicate scope": {role: "authenticated", scope: "openid openid"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
					"access_token": "new-access", "refresh_token": "new-refresh",
					"token_type": "bearer", "scope": test.scope,
				}))
			}))
			t.Cleanup(server.Close)
			now := time.Now().UTC().Truncate(time.Second)
			cfg := testConfig(server.URL)
			client, err := NewClient(cfg, nil, server.Client())
			require.NoError(t, err)
			claims := refreshClaims(now, cfg.Issuer)
			claims["role"] = test.role
			sessionClient, err := NewSessionClient(client, refreshValidatorStub{accessClaims: claims})
			require.NoError(t, err)
			sessionClient.clock = func() time.Time { return now }

			_, err = sessionClient.RefreshProviderTokens(
				context.Background(), providerRefreshRequest(t, cfg.Issuer, now),
			)
			require.ErrorIs(t, err, auth.ErrProviderRefreshRejected)
		})
	}
}

func TestSessionClientSignOutScopesAndResidualAccess(t *testing.T) {
	var scopes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scopes = append(scopes, r.URL.Query().Get("scope"))
		require.Equal(t, "Bearer current-access", r.Header.Get("Authorization"))
		require.Equal(t, "publishable-key", r.Header.Get("apikey"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	cfg := testConfig(server.URL)
	client, err := NewClient(cfg, nil, server.Client())
	require.NoError(t, err)
	sessionClient, err := NewSessionClient(client, refreshValidatorStub{})
	require.NoError(t, err)
	now := time.Now().UTC()
	sessionClient.clock = func() time.Time { return now }
	tokens := revocationTokenSet(
		t, now, client.config.Issuer,
		"5f090ad0-09fb-49e0-884d-a4453d1a7c33", "provider-session-1",
	)
	expires := tokens.AccessExpiresAt()

	current, err := sessionClient.SignOut(context.Background(), tokens, SignOutCurrent)
	require.NoError(t, err)
	require.Equal(t, auth.ProviderRemoteRevocationSucceeded, current.Status)
	require.Equal(t, expires, current.ResidualAccessExpires)
	all, err := sessionClient.SignOut(context.Background(), tokens, SignOutAll)
	require.NoError(t, err)
	require.Equal(t, auth.ProviderRemoteRevocationSucceeded, all.Status)
	named, err := sessionClient.SignOut(context.Background(), tokens, SignOutNamed)
	require.NoError(t, err)
	require.Equal(t, auth.ProviderRemoteRevocationUnsupported, named.Status)
	revoked, err := sessionClient.RevokeProviderSession(context.Background(), auth.ProviderRevocationRequest{
		Session: providerRefreshRequest(t, client.config.Issuer, now).Session,
		Tokens:  tokens,
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderRemoteRevocationSucceeded, revoked.Status)
	require.Equal(t, []string{"local", "global", "local"}, scopes)
}

func TestSessionClientRejectsUnboundRevocationBeforeTransport(t *testing.T) {
	now := time.Now().UTC()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	sessionClient, err := NewSessionClient(client, refreshValidatorStub{})
	require.NoError(t, err)
	sessionClient.clock = func() time.Time { return now }
	session := providerRefreshRequest(t, client.config.Issuer, now).Session

	tests := map[string]struct {
		session auth.ProviderSession
		tokens  auth.ProviderTokenSet
	}{
		"missing context": {
			session: session,
			tokens: func() auth.ProviderTokenSet {
				value, createErr := auth.NewProviderTokenSet(auth.ProviderTokenSetInput{
					AccessToken: auth.NewSecret("current-access"),
				})
				require.NoError(t, createErr)
				return value
			}(),
		},
		"wrong issuer": {
			session: session,
			tokens: revocationTokenSet(
				t, now, "https://other-project.supabase.co/auth/v1",
				session.Principal.ProviderSubject, session.Principal.ProviderSessionID,
			),
		},
		"wrong user": {
			session: session,
			tokens: revocationTokenSet(
				t, now, client.config.Issuer,
				"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", session.Principal.ProviderSessionID,
			),
		},
		"wrong session": {
			session: session,
			tokens: revocationTokenSet(
				t, now, client.config.Issuer,
				session.Principal.ProviderSubject, "different-provider-session",
			),
		},
		"wrong project binding": {
			session: func() auth.ProviderSession {
				value := session
				value.Binding.ClientID = "different-client"
				return value
			}(),
			tokens: revocationTokenSet(
				t, now, client.config.Issuer,
				session.Principal.ProviderSubject, session.Principal.ProviderSessionID,
			),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, revokeErr := sessionClient.RevokeProviderSession(
				context.Background(),
				auth.ProviderRevocationRequest{Session: test.session, Tokens: test.tokens},
			)
			require.ErrorIs(t, revokeErr, auth.ErrProviderOperationUnauthorized)
		})
	}
	require.Zero(t, calls.Load())
}

func TestSessionClientReconciliationIsExplicitlyUnknown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	sessionClient, err := NewSessionClient(client, refreshValidatorStub{})
	require.NoError(t, err)
	result, err := sessionClient.ReconcileProviderRefresh(context.Background(), auth.ProviderRefreshReconcileRequest{})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderRefreshReconcileUnknown, result.Status)
}
