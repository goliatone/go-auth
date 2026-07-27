package supabase

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	auth "github.com/goliatone/go-auth"
	"github.com/stretchr/testify/require"
)

func TestAdminLifecycleRecordsSecretFreeSuccessAndFailure(t *testing.T) {
	var transportCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		transportCalls.Add(1)
		_, _ = w.Write([]byte(`{"id":"5f090ad0-09fb-49e0-884d-a4453d1a7c33"}`))
	}))
	defer server.Close()

	var events []auth.ActivityEvent
	client, err := NewClient(
		testConfig(server.URL),
		nil,
		server.Client(),
		WithActivitySink(auth.ActivitySinkFunc(func(_ context.Context, event auth.ActivityEvent) error {
			events = append(events, event)
			return nil
		})),
	)
	require.NoError(t, err)
	admin, err := NewAdminClient(client)
	require.NoError(t, err)

	operation := authorizedOperation(auth.ProviderActionInvite, "user@example.com")
	operation.Actor.ID = "eyJhbGciOiJIUzI1NiJ9.actor.signature"
	operation.Reason = "cookie=session-secret"
	result, err := admin.Invite(context.Background(), auth.InviteRequest{
		Operation: operation,
		Email:     "user@example.com",
		ReturnURL: server.URL + "/client/callback",
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderOperationSucceeded, result.Status)

	failedOperation := operation
	failedOperation.OperationID = "failed-operation"
	_, err = admin.Invite(context.Background(), auth.InviteRequest{
		Operation: failedOperation,
		Email:     "user@example.com",
		ReturnURL: "https://attacker.example/callback",
	})
	require.ErrorIs(t, err, auth.ErrProviderOperationInvalid)

	require.Equal(t, int32(1), transportCalls.Load())
	require.Len(t, events, 2)
	require.Equal(t, auth.ProviderOperationSucceeded, events[0].Metadata["result"])
	require.Equal(t, auth.ProviderOperationFailed, events[1].Metadata["result"])
	encoded, err := json.Marshal(events)
	require.NoError(t, err)
	serialized := string(encoded)
	for _, raw := range []string{
		"user@example.com",
		"eyJhbGciOiJIUzI1NiJ9.actor.signature",
		"session-secret",
		"failed-operation",
	} {
		require.NotContains(t, serialized, raw)
	}
}

func TestLifecycleAuditFailureIsVisibleWithoutChangingProviderResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"5f090ad0-09fb-49e0-884d-a4453d1a7c33"}`))
	}))
	defer server.Close()

	var auditErr error
	client, err := NewClient(
		testConfig(server.URL),
		nil,
		server.Client(),
		WithActivitySink(auth.ActivitySinkFunc(func(context.Context, auth.ActivityEvent) error {
			return errors.New("audit unavailable")
		})),
		WithActivityErrorHandler(func(_ context.Context, err error) {
			auditErr = err
		}),
	)
	require.NoError(t, err)
	admin, err := NewAdminClient(client)
	require.NoError(t, err)

	result, err := admin.Invite(context.Background(), auth.InviteRequest{
		Operation: authorizedOperation(auth.ProviderActionInvite, "user@example.com"),
		Email:     "user@example.com",
		ReturnURL: server.URL + "/client/callback",
	})

	require.NoError(t, err)
	require.Equal(t, auth.ProviderOperationSucceeded, result.Status)
	require.Error(t, auditErr)
	require.True(t, strings.Contains(auditErr.Error(), "audit unavailable"))
}
