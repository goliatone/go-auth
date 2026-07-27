package supabase

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/stretchr/testify/require"
)

func authorizedOperation(action auth.ProviderOperationAction, subject string) auth.AuthorizedOperationContext {
	return auth.AuthorizedOperationContext{
		OperationID:  "operation-1",
		Action:       action,
		Permission:   "identity.manage",
		Actor:        auth.ActorRef{ID: "admin-1", Type: "user"},
		Target:       auth.ProviderOperationTarget{Provider: ProviderKey, Subject: subject},
		Reason:       "support request",
		Environment:  "test",
		RequestID:    "request-1",
		AuthorizedAt: time.Now().UTC(),
	}
}

func TestInvitationAndRecoveryUseNarrowCredentialBoundaries(t *testing.T) {
	type observed struct {
		path          string
		authorization string
		apiKey        string
		body          map[string]any
	}
	seen := make(chan observed, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		seen <- observed{
			path: r.URL.Path, authorization: r.Header.Get("Authorization"),
			apiKey: r.Header.Get("apikey"), body: body,
		}
		w.Header().Set("X-Request-ID", "provider-request")
		_, _ = io.WriteString(w, `{"id":"5f090ad0-09fb-49e0-884d-a4453d1a7c33"}`)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	admin, err := NewAdminClient(client)
	require.NoError(t, err)

	invite, err := admin.Invite(context.Background(), auth.InviteRequest{
		Operation: authorizedOperation(auth.ProviderActionInvite, "user@example.com"),
		Email:     "user@example.com",
		ReturnURL: server.URL + "/client/callback",
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderDeliverySent, invite.Delivery)

	recovery, err := admin.StartRecovery(context.Background(), auth.RecoveryRequest{
		Operation: authorizedOperation(auth.ProviderActionStartRecovery, "user@example.com"),
		Email:     "user@example.com",
		ReturnURL: server.URL + "/client/callback",
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderDeliverySent, recovery.Delivery)

	inviteRequest := <-seen
	recoveryRequest := <-seen
	require.Equal(t, "/auth/v1/invite", inviteRequest.path)
	require.Equal(t, "Bearer admin-secret", inviteRequest.authorization)
	require.Equal(t, "admin-secret", inviteRequest.apiKey)
	require.Equal(t, "/auth/v1/recover", recoveryRequest.path)
	require.Equal(t, "Bearer publishable-key", recoveryRequest.authorization)
	require.Equal(t, "publishable-key", recoveryRequest.apiKey)
	require.NotContains(t, inviteRequest.authorization, "management-secret")
	require.NotContains(t, recoveryRequest.authorization, "management-secret")
}

func TestDeliveryValidationFailsBeforeProviderAndMapsDuplicate(t *testing.T) {
	var calls atomic.Int32
	status := atomic.Int32{}
	status.Store(http.StatusConflict)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, `{"code":"user_already_exists"}`)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	admin, err := NewAdminClient(client)
	require.NoError(t, err)

	outcome, err := admin.Invite(context.Background(), auth.InviteRequest{
		Operation: authorizedOperation(auth.ProviderActionInvite, "user@example.com"),
		Email:     "user@example.com",
		ReturnURL: server.URL + "/client/callback",
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderDeliveryDuplicate, outcome.Delivery)
	require.Equal(t, int32(1), calls.Load())

	operation := authorizedOperation(auth.ProviderActionInvite, "other@example.com")
	_, err = admin.Invite(context.Background(), auth.InviteRequest{
		Operation: operation,
		Email:     "user@example.com",
		ReturnURL: server.URL + "/client/callback",
	})
	require.ErrorIs(t, err, auth.ErrProviderOperationInvalid)
	_, err = admin.Invite(context.Background(), auth.InviteRequest{
		Operation: authorizedOperation(auth.ProviderActionInvite, "user@example.com"),
		Email:     "user@example.com",
		ReturnURL: "https://attacker.example/callback",
	})
	require.ErrorIs(t, err, auth.ErrProviderOperationInvalid)
	require.Equal(t, int32(1), calls.Load())
}

func TestAmbiguousDeliveryIsPendingAndAttemptedOnce(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client(), WithRetryPolicy(RetryPolicy{MaxAttempts: 3}))
	require.NoError(t, err)
	admin, err := NewAdminClient(client)
	require.NoError(t, err)
	outcome, err := admin.Invite(context.Background(), auth.InviteRequest{
		Operation: authorizedOperation(auth.ProviderActionInvite, "user@example.com"),
		Email:     "user@example.com",
		ReturnURL: server.URL + "/client/callback",
	})
	require.ErrorIs(t, err, auth.ErrProviderOperationPending)
	require.Equal(t, auth.ProviderDeliveryPending, outcome.Delivery)
	require.Equal(t, int32(1), calls.Load())
}

func TestAccountLifecycleNormalizesStateAndSessionEffects(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		now := time.Now().UTC()
		response := map[string]any{
			"id":         "5f090ad0-09fb-49e0-884d-a4453d1a7c33",
			"updated_at": now,
		}
		if r.Method == http.MethodPut {
			var body map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			if body["ban_duration"] != "none" {
				response["banned_until"] = now.Add(time.Hour)
			}
		}
		require.NoError(t, json.NewEncoder(w).Encode(response))
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	admin, err := NewAdminClient(client)
	require.NoError(t, err)
	subject := "5f090ad0-09fb-49e0-884d-a4453d1a7c33"

	suspended, err := admin.Suspend(context.Background(), auth.AccountLifecycleRequest{
		Operation: authorizedOperation(auth.ProviderActionSuspend, subject),
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderAccountStateSuspended, suspended.State)
	require.Equal(t, auth.ProviderSessionEffectAllForUser, suspended.ProviderSessionEffect)

	active, err := admin.Activate(context.Background(), auth.AccountLifecycleRequest{
		Operation: authorizedOperation(auth.ProviderActionActivate, subject),
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderAccountStateActive, active.State)
	require.Equal(t, auth.ProviderSessionEffectNone, active.ProviderSessionEffect)

	state, err := admin.GetAccountState(context.Background(), auth.AccountLifecycleRequest{
		Operation: authorizedOperation(auth.ProviderActionGetAccountState, subject),
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderAccountStateActive, state.State)
	require.Equal(t, int32(3), calls.Load())
}

func TestAccountLifecycleRejectsBadTargetAndSurfacesPending(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	admin, err := NewAdminClient(client)
	require.NoError(t, err)

	_, err = admin.Suspend(context.Background(), auth.AccountLifecycleRequest{
		Operation: authorizedOperation(auth.ProviderActionSuspend, "not-a-uuid"),
	})
	require.ErrorIs(t, err, auth.ErrProviderOperationInvalid)
	require.Zero(t, calls.Load())

	unauthorized := authorizedOperation(auth.ProviderActionSuspend, "5f090ad0-09fb-49e0-884d-a4453d1a7c33")
	unauthorized.Permission = ""
	_, err = admin.Suspend(context.Background(), auth.AccountLifecycleRequest{Operation: unauthorized})
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)
	require.Zero(t, calls.Load())

	result, err := admin.Suspend(context.Background(), auth.AccountLifecycleRequest{
		Operation: authorizedOperation(auth.ProviderActionSuspend, "5f090ad0-09fb-49e0-884d-a4453d1a7c33"),
	})
	require.ErrorIs(t, err, auth.ErrProviderOperationPending)
	require.Equal(t, auth.ProviderOperationPending, result.Status)
	require.Equal(t, auth.ProviderSessionEffectAllForUser, result.ProviderSessionEffect)
	require.Equal(t, "request-1", result.ProviderRequestID)
	require.Equal(t, int32(1), calls.Load())
}

func TestAccountLifecycleMapsAlreadyCompleteAndRejectsWrongTargetResponse(t *testing.T) {
	mode := atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if mode.Load() == 0 {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"code":"already_suspended"}`)
			return
		}
		_, _ = io.WriteString(w, `{"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","updated_at":"2026-07-26T00:00:00Z"}`)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	admin, err := NewAdminClient(client)
	require.NoError(t, err)
	subject := "5f090ad0-09fb-49e0-884d-a4453d1a7c33"

	result, err := admin.Suspend(context.Background(), auth.AccountLifecycleRequest{
		Operation: authorizedOperation(auth.ProviderActionSuspend, subject),
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderOperationAlreadyComplete, result.Status)
	require.Equal(t, auth.ProviderAccountStateSuspended, result.State)

	mode.Store(1)
	_, err = admin.GetAccountState(context.Background(), auth.AccountLifecycleRequest{
		Operation: authorizedOperation(auth.ProviderActionGetAccountState, subject),
	})
	require.ErrorIs(t, err, ErrProviderUnavailable)
}
