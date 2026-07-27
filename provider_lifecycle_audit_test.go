package auth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProviderLifecycleActivityEventMapsTypedContext(t *testing.T) {
	operation := coordinatorOperation()
	operation.Action = ProviderActionSuspend
	outcome := ProviderOperationOutcome{
		Status: ProviderOperationPending, Retryable: true,
		ProviderRequestID:     "provider-request",
		ProviderSessionEffect: ProviderSessionEffectAllForUser,
		ResidualAccessExpires: time.Now().Add(time.Hour).UTC(),
	}
	event, err := NewProviderLifecycleActivityEvent(operation, outcome, time.Now().UTC())
	require.NoError(t, err)
	require.Equal(t, ActivityEventProviderAccountSuspend, event.EventType)
	require.Equal(t, string(FingerprintProviderAuditValue(operation.Actor.ID)), event.Actor.ID)
	require.Equal(t, string(FingerprintProviderAuditValue(operation.Actor.Type)), event.Actor.Type)
	require.Equal(t, string(FingerprintProviderAuditValue("app-user-1")), event.UserID)
	require.Equal(t, ProviderOperationPending, event.Metadata["result"])
	require.Equal(t, FingerprintProviderAuditValue("provider-request"), event.Metadata["provider_request_id"])
}

func TestProviderLifecycleActivityEventMapsOutcomeStatuses(t *testing.T) {
	t.Parallel()

	for _, status := range []ProviderOperationStatus{
		ProviderOperationSucceeded,
		ProviderOperationPending,
		ProviderOperationUnsupported,
		ProviderOperationFailed,
	} {
		t.Run(string(status), func(t *testing.T) {
			t.Parallel()

			operation := coordinatorOperation()
			operation.Action = ProviderActionRemoveFactor
			event, err := NewProviderLifecycleActivityEvent(
				operation,
				ProviderOperationOutcome{Status: status},
				time.Time{},
			)

			require.NoError(t, err)
			require.Equal(t, ActivityEventProviderFactorRemove, event.EventType)
			require.Equal(t, status, event.Metadata["result"])
			require.False(t, event.OccurredAt.IsZero())
		})
	}
}

func TestProviderLifecycleActivityEventRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	operation := coordinatorOperation()
	operation.Action = ProviderOperationAction("unknown")
	_, err := NewProviderLifecycleActivityEvent(
		operation,
		ProviderOperationOutcome{Status: ProviderOperationSucceeded},
		time.Now(),
	)
	require.ErrorIs(t, err, ErrProviderOperationUnauthorized)

	operation = coordinatorOperation()
	_, err = NewProviderLifecycleActivityEvent(
		operation,
		ProviderOperationOutcome{},
		time.Now(),
	)
	require.ErrorIs(t, err, ErrProviderOperationInvalid)
}

func TestProviderLifecycleActivityEventNeverRetainsRawFreeFormValues(t *testing.T) {
	t.Parallel()

	operation := coordinatorOperation()
	operation.Actor.ID = "eyJhbGciOiJIUzI1NiJ9.actor.signature"
	operation.Actor.Type = "cookie=session-secret"
	operation.Target.ApplicationSubject = "opaque-application-secret"
	operation.Target.Subject = "provider-secret"
	operation.Target.ObjectID = "authorization-code-secret"
	operation.Reason = "short-secret"
	operation.RequestID = "request-secret"
	operation.ProviderSessionID = "session-secret"
	outcome := ProviderOperationOutcome{
		Status:            ProviderOperationSucceeded,
		ProviderRequestID: "provider-request-secret",
	}

	event, err := NewProviderLifecycleActivityEvent(operation, outcome, time.Now().UTC())
	require.NoError(t, err)
	encoded, err := json.Marshal(event)
	require.NoError(t, err)
	serialized := string(encoded)
	for _, raw := range []string{
		"eyJhbGciOiJIUzI1NiJ9.actor.signature",
		"session-secret",
		"short-secret",
		"authorization-code-secret",
		"provider-request-secret",
	} {
		require.NotContains(t, serialized, raw)
	}
	require.Contains(t, strings.ToLower(serialized), providerAuditFingerprintPrefix)
}
