package auth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProviderRemoteRevocationOutcomeValidationFailsClosed(t *testing.T) {
	t.Parallel()
	for name, outcome := range map[string]ProviderRemoteRevocationOutcome{
		"empty": {},
		"unknown": {
			Status: "invented",
		},
		"pending_without_retry": {
			Status: ProviderRemoteRevocationPending,
		},
		"success_with_retry": {
			Status: ProviderRemoteRevocationSucceeded, Retryable: true,
		},
		"unsupported_with_retry": {
			Status: ProviderRemoteRevocationUnsupported, Retryable: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Error(t, outcome.Validate())
		})
	}
	require.NoError(t, (ProviderRemoteRevocationOutcome{
		Status: ProviderRemoteRevocationFailed, Retryable: false,
	}).Validate())
	require.NoError(t, (ProviderRemoteRevocationOutcome{
		Status: ProviderRemoteRevocationFailed, Retryable: true,
	}).Validate())
}

func TestProviderSessionContractsDoNotExposeSecrets(t *testing.T) {
	t.Parallel()

	envelope := TokenEnvelope{
		Version:    1,
		Algorithm:  "AES-256-GCM",
		KeyID:      "key-1",
		Nonce:      []byte("012345678901"),
		Ciphertext: []byte("provider-token-plaintext"),
	}
	formatted := fmt.Sprintf("%v %#v", envelope, envelope)
	require.NotContains(t, formatted, "provider-token-plaintext")

	logged := envelope.LogValue()
	require.Equal(t, slog.KindGroup, logged.Kind())
	require.NotContains(t, logged.String(), "provider-token-plaintext")

	session := ProviderSession{
		ID:             "internal-id",
		LocalSessionID: "audit-id",
		Status:         ProviderSessionAvailable,
		TokenRevision:  4,
	}
	require.NotContains(t, session.String(), "provider-token-plaintext")
}

func TestPrincipalSnapshotRoundTrip(t *testing.T) {
	t.Parallel()

	principal, err := NewAuthenticatedPrincipal(AuthenticatedPrincipalInput{
		ApplicationSubject: "user-1",
		Provider:           "oidc",
		ProviderSubject:    "provider-user-1",
		ProviderSessionID:  "provider-sid",
		LocalSessionID:     "local-session",
		ClientID:           "client-1",
		AssuranceLevel:     "aal2",
		AssuranceMethods:   []string{"totp"},
		AuthenticationAt:   time.Unix(1_700_000_000, 0).UTC(),
		TenantID:           "tenant-1",
		Metadata:           map[string]string{"safe": "value"},
	})
	require.NoError(t, err)

	roundTrip, err := NewPrincipalSnapshot(principal).Principal()
	require.NoError(t, err)
	require.Equal(t, principal.ApplicationSubject(), roundTrip.ApplicationSubject())
	require.Equal(t, principal.ProviderSubject(), roundTrip.ProviderSubject())
	require.Equal(t, principal.LocalSessionID(), roundTrip.LocalSessionID())
	require.Equal(t, principal.AssuranceMethods(), roundTrip.AssuranceMethods())
}

func TestProviderSessionContractsKeepSecretsNonSerializable(t *testing.T) {
	t.Parallel()

	secret := NewSecret("provider-access-token")
	_, err := json.Marshal(secret)
	require.ErrorIs(t, err, ErrSecretSerialization)
	require.False(t, strings.Contains(fmt.Sprintf("%v", secret), "provider-access-token"))
}

func TestProviderSessionBindingNormalizesHostAndIssuer(t *testing.T) {
	t.Parallel()

	left := ProviderSessionBinding{
		Host: " APP.EXAMPLE.COM ", ApplicationID: "app", Environment: "prod",
		Provider: "oidc", Issuer: "https://issuer.example.com/", ClientID: "client",
	}
	right := ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "prod",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client",
	}
	require.NoError(t, left.Validate())
	require.True(t, left.Equal(right))
}
