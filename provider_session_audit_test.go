package auth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProviderSessionActivityEventContainsOnlyTypedFingerprintMetadata(t *testing.T) {
	const (
		rawSubject   = "subject-canary@example.test"
		rawSessionID = "session-canary-123"
		rawProvider  = "provider-canary"
		rawApp       = "application-canary"
		rawEnv       = "environment-canary"
		rawReason    = "authorization: bearer reason-canary"
		rawTarget    = "payments-canary"
	)
	session := ProviderSession{
		LocalSessionID: rawSessionID,
		Principal:      PrincipalSnapshot{ApplicationSubject: rawSubject},
		Binding: ProviderSessionBinding{
			Provider: rawProvider, ApplicationID: rawApp, Environment: rawEnv,
		},
		Status:        ProviderSessionRevoked,
		TokenRevision: 7,
	}
	event, err := NewProviderSessionActivityEvent(
		ActivityEventProviderSessionRevoked,
		session,
		ProviderSessionActivityMetadata{
			Result:          "failed",
			Reason:          ProviderSessionReasonFromLegacy(rawReason),
			RemoteStatus:    ProviderRemoteRevocationFailed,
			RemoteRetryable: true,
			Target:          rawTarget,
		},
		time.Now().UTC(),
	)
	require.NoError(t, err)

	payload, err := json.Marshal(event)
	require.NoError(t, err)
	serialized := strings.ToLower(string(payload))
	for _, canary := range []string{
		rawSubject, rawSessionID, rawProvider, rawApp, rawEnv, rawReason, rawTarget,
	} {
		require.NotContains(t, serialized, strings.ToLower(canary))
	}
	require.Equal(t, ProviderSessionReasonLegacyExternal, event.Metadata["reason_code"])
	require.Equal(t, FingerprintProviderAuditValue(rawReason), event.Metadata["reason_fingerprint"])
}

func TestProviderSessionReasonEncodingNeverPersistsLegacyDetail(t *testing.T) {
	const raw = "customer email alice@example.test, bearer reason-secret"
	encoded := EncodeProviderSessionReason(ProviderSessionReasonFromLegacy(raw))

	require.NotContains(t, encoded, raw)
	decoded := ParseProviderSessionReason(encoded)
	require.Equal(t, ProviderSessionReasonLegacyExternal, decoded.Code)
	require.Equal(t, FingerprintProviderAuditValue(raw), decoded.DetailFingerprint)
}

func TestProviderSessionReasonMalformedFingerprintIsNormalized(t *testing.T) {
	const rawSuffix = "raw-secret@example.test"
	encoded := EncodeProviderSessionReason(ProviderSessionReason{
		Code:              ProviderSessionReasonLogout,
		DetailFingerprint: ProviderAuditFingerprint("sha256:" + rawSuffix),
	})
	require.NotContains(t, encoded, rawSuffix)
	decoded := ParseProviderSessionReason("logout|sha256:" + rawSuffix)
	require.Equal(t, ProviderSessionReasonLogout, decoded.Code)
	require.Equal(
		t,
		FingerprintProviderAuditValue("sha256:"+rawSuffix),
		decoded.DetailFingerprint,
	)
	require.NotContains(t, string(decoded.DetailFingerprint), rawSuffix)

	session := ProviderSession{
		LocalSessionID: "session-1",
		Principal:      PrincipalSnapshot{ApplicationSubject: "user-1"},
		Binding: ProviderSessionBinding{
			Provider: "oidc", ApplicationID: "app", Environment: "test",
		},
		Status: ProviderSessionRevoked, TokenRevision: 1,
	}
	event, err := NewProviderSessionActivityEvent(
		ActivityEventProviderSessionRevoked,
		session,
		ProviderSessionActivityMetadata{
			Reason: ProviderSessionReason{
				Code:              ProviderSessionReasonLogout,
				DetailFingerprint: ProviderAuditFingerprint("sha256:" + rawSuffix),
			},
		},
		time.Now().UTC(),
	)
	require.NoError(t, err)
	require.Equal(
		t,
		FingerprintProviderAuditValue("sha256:"+rawSuffix),
		event.Metadata["reason_fingerprint"],
	)
}
