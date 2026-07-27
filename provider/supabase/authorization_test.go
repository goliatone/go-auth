package supabase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/stretchr/testify/require"
)

const (
	authorizationID  = "authorization_12345"
	oauthClientID    = "momentum-client"
	decisionProofKey = "0123456789abcdef0123456789abcdef"
)

func authorizationOperation(action auth.ProviderOperationAction, session auth.ProviderUserSession) auth.AuthorizedOperationContext {
	operation := authorizedOperation(action, session.Principal.ProviderSubject())
	operation.Target.ObjectID = authorizationID
	operation.ProviderSessionID = session.Principal.ProviderSessionID()
	return operation
}

func authorizationServiceForTest(
	t *testing.T,
	server *httptest.Server,
	tokens auth.UserTokenProvider,
	csrf AuthorizationCSRFVerifier,
	now time.Time,
	options ...ClientOption,
) (*AuthorizationService, auth.ProviderUserSession) {
	t.Helper()
	cfg := testConfig(server.URL)
	client, err := NewClient(cfg, tokens, server.Client(), options...)
	require.NoError(t, err)
	service, err := NewAuthorizationService(AuthorizationServiceConfig{
		Client: client,
		Clients: map[string]AuthorizationClientPolicy{
			oauthClientID: {
				Name: "Momentum App", RedirectURLs: []string{server.URL + "/client/callback"},
				AllowedScopes: []string{"openid", "profile"},
			},
		},
		CSRFVerifier:     csrf,
		DecisionProofKey: auth.NewSecret(decisionProofKey),
		Clock:            func() time.Time { return now },
	})
	require.NoError(t, err)
	session := testProviderUserSession(t, now.Add(time.Hour))
	session.Binding.Issuer = cfg.Issuer
	return service, session
}

func allowCSRF() AuthorizationCSRFVerifier {
	return AuthorizationCSRFVerifierFunc(func(context.Context, AuthorizationCSRFContext) error { return nil })
}

func decisionProofForTest(
	t *testing.T,
	service *AuthorizationService,
	session auth.ProviderUserSession,
	scopes []string,
	now time.Time,
) auth.Secret {
	t.Helper()
	proof, err := service.issueAuthorizationDecisionProof(auth.AuthorizationDetails{
		AuthorizationID: authorizationID,
		ClientID:        oauthClientID,
		Scopes:          scopes,
		ExpiresAt:       now.Add(5 * time.Minute),
	}, session, now)
	require.NoError(t, err)
	return proof
}

func TestAuthorizationServiceRejectsAmbiguousClientPolicy(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)

	policy := AuthorizationClientPolicy{
		Name: "Momentum App", RedirectURLs: []string{server.URL + "/callback"},
		AllowedScopes: []string{"openid"},
	}
	for name, clients := range map[string]map[string]AuthorizationClientPolicy{
		"normalized client ID collision": {
			"client": policy, " client ": policy,
		},
		"duplicate redirect": {
			"client": {
				Name: "Momentum App",
				RedirectURLs: []string{
					server.URL + "/callback",
					server.URL + "/callback",
				},
				AllowedScopes: []string{"openid"},
			},
		},
		"duplicate scope": {
			"client": {
				Name:          "Momentum App",
				RedirectURLs:  []string{server.URL + "/callback"},
				AllowedScopes: []string{"openid", "openid"},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := NewAuthorizationService(AuthorizationServiceConfig{
				Client: client, Clients: clients, CSRFVerifier: allowCSRF(),
				DecisionProofKey: auth.NewSecret(decisionProofKey),
			})
			require.ErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestAuthorizationServiceRequiresDedicatedProofKey(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	policy := map[string]AuthorizationClientPolicy{
		oauthClientID: {
			Name: "Momentum App", RedirectURLs: []string{server.URL + "/callback"},
			AllowedScopes: []string{"openid"},
		},
	}
	for name, key := range map[string]auth.Secret{
		"missing":     {},
		"too short":   auth.NewSecret("short"),
		"client":      client.config.ClientSecret,
		"admin":       client.config.AdminCredential,
		"publishable": client.config.PublishableKey,
		"management":  client.config.ManagementCredential,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, createErr := NewAuthorizationService(AuthorizationServiceConfig{
				Client: client, Clients: policy, CSRFVerifier: allowCSRF(),
				DecisionProofKey: key,
			})
			require.ErrorIs(t, createErr, ErrInvalidConfig)
		})
	}
}

func TestAuthorizationDetailsAreUserBoundAndSanitized(t *testing.T) {
	now := time.Now().UTC()
	var calls atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, "Bearer current-user-token", r.Header.Get("Authorization"))
		require.Equal(t, "publishable-key", r.Header.Get("apikey"))
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"authorization_id": authorizationID,
			"client_id":        oauthClientID,
			"client_name":      "untrusted provider name",
			"scopes":           []string{"openid", "profile"},
			"redirect_uri":     server.URL + "/client/callback",
			"expires_at":       now.Add(5 * time.Minute),
			"access_token":     "must-not-pass-through",
		}))
	}))
	defer server.Close()
	service, session := authorizationServiceForTest(
		t, server, &tokenProviderStub{token: auth.NewSecret("current-user-token")}, allowCSRF(), now,
	)
	details, err := service.GetAuthorizationDetails(context.Background(), auth.AuthorizationDetailsRequest{
		Operation: authorizationOperation(auth.ProviderActionAuthorizationDetails, session),
		Continuation: auth.AuthorizationContinuation{
			AuthorizationID: authorizationID, Environment: "test", ExpiresAt: now.Add(10 * time.Minute),
		},
		Session: session,
	})
	require.NoError(t, err)
	require.Equal(t, "Momentum App", details.ClientName)
	require.Equal(t, []string{"openid", "profile"}, details.Scopes)
	require.False(t, details.DecisionProof.IsZero())
	encoded, err := json.Marshal(details)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "must-not-pass-through")
	require.NotContains(t, string(encoded), details.DecisionProof.Reveal())
	require.Equal(t, int32(1), calls.Load())
}

func TestAuthorizationDetailsRejectMissingSessionAndUnknownClientWithoutOracle(t *testing.T) {
	now := time.Now().UTC()
	var calls atomic.Int32
	unknownClient := atomic.Bool{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		clientID := oauthClientID
		if unknownClient.Load() {
			clientID = "unknown-client"
		}
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"authorization_id": authorizationID, "client_id": clientID,
			"scopes": []string{"openid"}, "redirect_uri": server.URL + "/client/callback",
			"expires_at": now.Add(5 * time.Minute),
		}))
	}))
	defer server.Close()
	service, session := authorizationServiceForTest(
		t, server, &tokenProviderStub{token: auth.NewSecret("current-user-token")}, allowCSRF(), now,
	)
	request := auth.AuthorizationDetailsRequest{
		Operation: authorizationOperation(auth.ProviderActionAuthorizationDetails, session),
		Continuation: auth.AuthorizationContinuation{
			AuthorizationID: authorizationID, Environment: "test", ExpiresAt: now.Add(10 * time.Minute),
		},
		Session: session,
	}
	request.Session = auth.ProviderUserSession{}
	_, err := service.GetAuthorizationDetails(context.Background(), request)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)
	require.Zero(t, calls.Load())

	request.Session = session
	unknownClient.Store(true)
	_, err = service.GetAuthorizationDetails(context.Background(), request)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)
	require.Equal(t, int32(1), calls.Load())
}

func TestAuthorizationApproveAndDenyReturnOnlyValidatedRedirect(t *testing.T) {
	now := time.Now().UTC()
	var actions []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Action string `json:"action"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		actions = append(actions, body.Action)
		redirect := server.URL + "/client/callback?code=provider-code&state=provider-state"
		if body.Action == "deny" {
			redirect = server.URL + "/client/callback?error=access_denied&state=provider-state"
		}
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"client_id": oauthClientID, "redirect_uri": redirect,
		}))
	}))
	defer server.Close()
	service, session := authorizationServiceForTest(
		t, server, &tokenProviderStub{token: auth.NewSecret("current-user-token")}, allowCSRF(), now,
	)
	approveRequest := auth.AuthorizationDecisionRequest{
		Operation:       authorizationOperation(auth.ProviderActionAuthorizationApprove, session),
		AuthorizationID: authorizationID,
		ClientID:        oauthClientID,
		Session:         session,
		Scopes:          []string{"openid"},
		CSRFBinding:     "csrf-proof",
		DecisionProof:   decisionProofForTest(t, service, session, []string{"openid"}, now),
	}
	approved, err := service.ApproveAuthorization(context.Background(), approveRequest)
	require.NoError(t, err)
	require.Contains(t, approved.HTTPRedirectURL(), "code=provider-code")

	denyRequest := approveRequest
	denyRequest.Operation = authorizationOperation(auth.ProviderActionAuthorizationDeny, session)
	denyRequest.Scopes = nil
	denied, err := service.DenyAuthorization(context.Background(), denyRequest)
	require.NoError(t, err)
	require.Contains(t, denied.HTTPRedirectURL(), "error=access_denied")
	require.Equal(t, []string{"approve", "deny"}, actions)

	for _, value := range []string{fmt.Sprintf("%+v", approved), string(mustJSON(t, approved))} {
		require.NotContains(t, value, "provider-code")
		require.NotContains(t, value, "provider-state")
	}
}

func TestAuthorizationDecisionRejectsCSRFOpenRedirectReplayAndSessionMismatch(t *testing.T) {
	now := time.Now().UTC()
	var calls atomic.Int32
	mode := atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		switch mode.Load() {
		case 1:
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"client_id": oauthClientID, "redirect_uri": "https://attacker.example/callback?code=secret",
			}))
		case 2:
			w.WriteHeader(http.StatusConflict)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	defer server.Close()
	csrf := AuthorizationCSRFVerifierFunc(func(_ context.Context, csrf AuthorizationCSRFContext) error {
		if csrf.Binding != "valid-csrf" {
			return errors.New("invalid CSRF")
		}
		return nil
	})
	service, session := authorizationServiceForTest(
		t, server, &tokenProviderStub{token: auth.NewSecret("current-user-token")}, csrf, now,
	)
	request := auth.AuthorizationDecisionRequest{
		Operation:       authorizationOperation(auth.ProviderActionAuthorizationApprove, session),
		AuthorizationID: authorizationID, ClientID: oauthClientID, Session: session,
		Scopes: []string{"openid"}, CSRFBinding: "bad-csrf",
		DecisionProof: decisionProofForTest(t, service, session, []string{"openid"}, now),
	}
	_, err := service.ApproveAuthorization(context.Background(), request)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)
	require.Zero(t, calls.Load())

	request.CSRFBinding = "valid-csrf"
	request.Operation.ProviderSessionID = "different-session"
	_, err = service.ApproveAuthorization(context.Background(), request)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)
	require.Zero(t, calls.Load())

	request.Operation.ProviderSessionID = session.Principal.ProviderSessionID()
	mode.Store(1)
	_, err = service.ApproveAuthorization(context.Background(), request)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)
	mode.Store(2)
	result, err := service.ApproveAuthorization(context.Background(), request)
	require.ErrorIs(t, err, auth.ErrProviderOperationConflict)
	require.Equal(t, auth.ProviderOperationConflict, result.Status)
	require.Equal(t, int32(2), calls.Load())
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return encoded
}

func TestAuthorizationDecisionRejectsExcessiveOrUnknownScopeBeforeTransportResult(t *testing.T) {
	now := time.Now().UTC()
	var calls atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"client_id":    oauthClientID,
			"redirect_uri": server.URL + "/client/callback?code=secret",
		}))
	}))
	defer server.Close()
	service, session := authorizationServiceForTest(
		t, server, &tokenProviderStub{token: auth.NewSecret("current-user-token")}, allowCSRF(), now,
	)
	request := auth.AuthorizationDecisionRequest{
		Operation:       authorizationOperation(auth.ProviderActionAuthorizationApprove, session),
		AuthorizationID: authorizationID, ClientID: oauthClientID, Session: session,
		Scopes: []string{"admin"}, CSRFBinding: "csrf",
		DecisionProof: decisionProofForTest(t, service, session, []string{"openid"}, now),
	}
	_, err := service.ApproveAuthorization(context.Background(), request)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)
	require.NotContains(t, strings.ToLower(err.Error()), "admin")
	require.Zero(t, calls.Load())
}

func TestAuthorizationDecisionRequiresDetailsContinuityAndFullyBoundCSRF(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	var decisionCalls atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"authorization_id": authorizationID,
				"client_id":        oauthClientID,
				"scopes":           []string{"openid"},
				"redirect_uri":     server.URL + "/client/callback",
				"expires_at":       now.Add(5 * time.Minute),
			}))
			return
		}
		decisionCalls.Add(1)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"client_id": oauthClientID,
			"redirect_uri": server.URL +
				"/client/callback?code=provider-code&state=provider-state",
		}))
	}))
	defer server.Close()

	var csrfCalls atomic.Int32
	csrf := AuthorizationCSRFVerifierFunc(func(_ context.Context, value AuthorizationCSRFContext) error {
		csrfCalls.Add(1)
		if value.AuthorizationID != authorizationID ||
			value.Binding != "bound-csrf" ||
			value.Action != auth.ProviderActionAuthorizationApprove ||
			value.ClientID != oauthClientID ||
			!slices.Equal(value.RequestedScopes, []string{"openid"}) ||
			!slices.Equal(value.GrantedScopes, []string{"openid"}) ||
			value.ProviderSessionID == "" ||
			value.ProviderSubject == "" ||
			value.Environment != "test" ||
			!value.DetailsExpiresAt.Equal(now.Add(5*time.Minute)) {
			return errors.New("CSRF context mismatch")
		}
		return nil
	})
	service, session := authorizationServiceForTest(
		t, server, &tokenProviderStub{token: auth.NewSecret("current-user-token")}, csrf, now,
	)
	details, err := service.GetAuthorizationDetails(context.Background(), auth.AuthorizationDetailsRequest{
		Operation: authorizationOperation(auth.ProviderActionAuthorizationDetails, session),
		Continuation: auth.AuthorizationContinuation{
			AuthorizationID: authorizationID,
			Environment:     "test",
			ExpiresAt:       now.Add(10 * time.Minute),
		},
		Session: session,
	})
	require.NoError(t, err)

	request := auth.AuthorizationDecisionRequest{
		Operation:       authorizationOperation(auth.ProviderActionAuthorizationApprove, session),
		AuthorizationID: authorizationID,
		ClientID:        oauthClientID,
		Session:         session,
		Scopes:          []string{"openid"},
		CSRFBinding:     "bound-csrf",
		DecisionProof:   details.DecisionProof,
	}
	_, err = service.ApproveAuthorization(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, int32(1), decisionCalls.Load())
	require.Equal(t, int32(1), csrfCalls.Load())

	missing := request
	missing.DecisionProof = auth.Secret{}
	_, err = service.ApproveAuthorization(context.Background(), missing)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)

	tampered := request
	tampered.DecisionProof = auth.NewSecret(details.DecisionProof.Reveal() + "tampered")
	_, err = service.ApproveAuthorization(context.Background(), tampered)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)

	changedClient := request
	changedClient.ClientID = "different-client"
	_, err = service.ApproveAuthorization(context.Background(), changedClient)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)

	changedScopes := request
	changedScopes.Scopes = []string{"profile"}
	_, err = service.ApproveAuthorization(context.Background(), changedScopes)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)

	deny := request
	deny.Operation = authorizationOperation(auth.ProviderActionAuthorizationDeny, session)
	deny.Scopes = nil
	_, err = service.DenyAuthorization(context.Background(), deny)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)

	require.Equal(t, int32(1), decisionCalls.Load())
	require.Equal(t, int32(2), csrfCalls.Load())
}

func TestAuthorizationLifecycleRecordsDetailsAndDecision(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"authorization_id": authorizationID,
				"client_id":        oauthClientID,
				"scopes":           []string{"openid"},
				"redirect_uri":     server.URL + "/client/callback",
				"expires_at":       now.Add(5 * time.Minute),
			}))
			return
		}
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"client_id": oauthClientID,
			"redirect_uri": server.URL +
				"/client/callback?code=provider-code&state=provider-state",
		}))
	}))
	defer server.Close()

	var events []auth.ActivityEvent
	service, session := authorizationServiceForTest(
		t,
		server,
		&tokenProviderStub{token: auth.NewSecret("current-user-token")},
		allowCSRF(),
		now,
		WithActivitySink(auth.ActivitySinkFunc(func(_ context.Context, event auth.ActivityEvent) error {
			events = append(events, event)
			return nil
		})),
	)
	details, err := service.GetAuthorizationDetails(context.Background(), auth.AuthorizationDetailsRequest{
		Operation: authorizationOperation(auth.ProviderActionAuthorizationDetails, session),
		Continuation: auth.AuthorizationContinuation{
			AuthorizationID: authorizationID,
			Environment:     "test",
			ExpiresAt:       now.Add(10 * time.Minute),
		},
		Session: session,
	})
	require.NoError(t, err)
	_, err = service.ApproveAuthorization(context.Background(), auth.AuthorizationDecisionRequest{
		Operation:       authorizationOperation(auth.ProviderActionAuthorizationApprove, session),
		AuthorizationID: authorizationID,
		ClientID:        oauthClientID,
		Session:         session,
		Scopes:          []string{"openid"},
		CSRFBinding:     "bound-csrf",
		DecisionProof:   details.DecisionProof,
	})
	require.NoError(t, err)

	require.Len(t, events, 2)
	require.Equal(t, auth.ActivityEventProviderAuthDetails, events[0].EventType)
	require.Equal(t, auth.ActivityEventProviderAuthApprove, events[1].EventType)
	require.Equal(t, auth.ProviderOperationSucceeded, events[0].Metadata["result"])
	require.Equal(t, auth.ProviderOperationSucceeded, events[1].Metadata["result"])
	encoded, err := json.Marshal(events)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), authorizationID)
	require.NotContains(t, string(encoded), "provider-code")
	require.NotContains(t, string(encoded), details.DecisionProof.Reveal())
}
