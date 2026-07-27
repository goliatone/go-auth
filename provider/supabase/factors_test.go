package supabase

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/stretchr/testify/require"
)

const (
	factorOwnerID = "5f090ad0-09fb-49e0-884d-a4453d1a7c33"
	factorID      = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

func factorRemovalOperation() auth.AuthorizedOperationContext {
	operation := authorizedOperation(auth.ProviderActionRemoveFactor, factorOwnerID)
	operation.Target.ObjectID = factorID
	return operation
}

func writeFactorSnapshot(t *testing.T, w http.ResponseWriter, states ...auth.ProviderFactorState) {
	t.Helper()
	now := time.Now().UTC()
	factors := make([]map[string]any, 0, len(states))
	for index, state := range states {
		id := factorID
		if index > 0 {
			id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		}
		factors = append(factors, map[string]any{
			"id": id, "factor_type": "totp", "status": state,
			"created_at": now, "updated_at": now,
		})
	}
	require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"factors": factors}))
}

func TestFactorLifecycleListsNormalizedFactors(t *testing.T) {
	now := time.Now().UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"factors": []map[string]any{
				{
					"id": factorID, "factor_type": "totp", "status": "verified",
					"friendly_name": "Authenticator", "created_at": now, "updated_at": now,
				},
				{
					"id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "factor_type": "future-factor",
					"status": "unverified", "created_at": now, "updated_at": now,
				},
			},
		}))
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	admin, err := NewAdminClient(client)
	require.NoError(t, err)
	result, err := admin.ListFactors(context.Background(), auth.FactorListRequest{
		Operation: authorizedOperation(auth.ProviderActionListFactors, factorOwnerID),
	})
	require.NoError(t, err)
	require.Len(t, result.Factors, 2)
	require.Equal(t, auth.ProviderFactorTOTP, result.Factors[0].Type)
	require.Equal(t, auth.ProviderFactorVerified, result.Factors[0].State)
	require.Equal(t, auth.ProviderFactorUnknown, result.Factors[1].Type)
	require.Equal(t, auth.ProviderFactorUnverified, result.Factors[1].State)
}

func TestFactorRemovalReportsVerifiedSessionAndAssuranceEffects(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == http.MethodGet {
			if calls.Load() == 1 {
				writeFactorSnapshot(t, w, auth.ProviderFactorVerified, auth.ProviderFactorVerified)
			} else {
				writeFactorSnapshot(t, w, auth.ProviderFactorUnverified)
			}
			return
		}
		require.Equal(t, http.MethodDelete, r.Method)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	admin, err := NewAdminClient(client)
	require.NoError(t, err)

	verified, err := admin.RemoveFactor(context.Background(), auth.FactorRemoveRequest{
		Operation:                factorRemovalOperation(),
		FactorID:                 factorID,
		KnownState:               auth.ProviderFactorVerified,
		RemainingVerifiedFactors: 2,
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderSessionEffectAllForUser, verified.ProviderSessionEffect)

	unverified, err := admin.RemoveFactor(context.Background(), auth.FactorRemoveRequest{
		Operation:  factorRemovalOperation(),
		FactorID:   factorID,
		KnownState: auth.ProviderFactorUnverified,
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderSessionEffectNone, unverified.ProviderSessionEffect)
	require.Equal(t, int32(4), calls.Load())
}

func TestFactorRemovalEnforcesLastFactorAndAuthorizationBeforeTransport(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, http.MethodGet, r.Method)
		writeFactorSnapshot(t, w, auth.ProviderFactorVerified)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	admin, err := NewAdminClient(client)
	require.NoError(t, err)

	result, err := admin.RemoveFactor(context.Background(), auth.FactorRemoveRequest{
		Operation:                factorRemovalOperation(),
		FactorID:                 factorID,
		KnownState:               auth.ProviderFactorVerified,
		RemainingVerifiedFactors: 1,
	})
	require.ErrorIs(t, err, auth.ErrProviderOperationConflict)
	require.Equal(t, auth.ProviderOperationConflict, result.Status)

	operation := factorRemovalOperation()
	operation.Permission = ""
	_, err = admin.RemoveFactor(context.Background(), auth.FactorRemoveRequest{
		Operation: operation, FactorID: factorID, KnownState: auth.ProviderFactorUnverified,
	})
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)
	require.Equal(t, int32(1), calls.Load())
}

func TestFactorRemovalMapsUnsupportedAndPendingWithoutDuplicateCalls(t *testing.T) {
	var calls atomic.Int32
	status := atomic.Int32{}
	status.Store(http.StatusNotImplemented)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == http.MethodGet {
			writeFactorSnapshot(t, w, auth.ProviderFactorVerified, auth.ProviderFactorVerified)
			return
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	admin, err := NewAdminClient(client)
	require.NoError(t, err)
	request := auth.FactorRemoveRequest{
		Operation:                factorRemovalOperation(),
		FactorID:                 factorID,
		KnownState:               auth.ProviderFactorVerified,
		RemainingVerifiedFactors: 2,
	}

	result, err := admin.RemoveFactor(context.Background(), request)
	require.ErrorIs(t, err, auth.ErrProviderOperationUnsupported)
	require.Equal(t, auth.ProviderOperationUnsupported, result.Status)
	status.Store(http.StatusServiceUnavailable)
	result, err = admin.RemoveFactor(context.Background(), request)
	require.ErrorIs(t, err, auth.ErrProviderOperationPending)
	require.Equal(t, auth.ProviderOperationPending, result.Status)
	require.Equal(t, auth.ProviderSessionEffectAllForUser, result.ProviderSessionEffect)
	require.Equal(t, int32(4), calls.Load())
}

func TestFactorRemovalRejectsTargetAndSnapshotMismatch(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, http.MethodGet, r.Method)
		writeFactorSnapshot(t, w, auth.ProviderFactorVerified, auth.ProviderFactorVerified)
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL), nil, server.Client())
	require.NoError(t, err)
	admin, err := NewAdminClient(client)
	require.NoError(t, err)

	targetMismatch := factorRemovalOperation()
	targetMismatch.Target.ObjectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	_, err = admin.RemoveFactor(context.Background(), auth.FactorRemoveRequest{
		Operation: targetMismatch, FactorID: factorID,
	})
	require.ErrorIs(t, err, auth.ErrProviderOperationUnauthorized)
	require.Zero(t, calls.Load())

	result, err := admin.RemoveFactor(context.Background(), auth.FactorRemoveRequest{
		Operation: factorRemovalOperation(), FactorID: factorID,
		KnownState: auth.ProviderFactorUnverified,
	})
	require.ErrorIs(t, err, auth.ErrProviderOperationConflict)
	require.Equal(t, auth.ProviderOperationConflict, result.Status)
	require.Equal(t, int32(1), calls.Load())
}
