package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProviderSessionManagerRequiresCompleteProductionOperations(t *testing.T) {
	t.Parallel()
	repository := &operationsRepositoryStub{}
	cipher := operationsCipherStub{}
	binding := ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "production",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client",
	}
	_, err := NewProviderSessionManager(ProviderSessionManagerConfig{
		Repository: repository, Cipher: cipher, Binding: binding,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
	})
	require.ErrorIs(t, err, ErrProviderSessionInvalid)

	operations := completeOperationsFixture()
	manager, err := NewProviderSessionManager(ProviderSessionManagerConfig{
		Repository: repository, Cipher: cipher, Binding: binding,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour, Operations: &operations,
	})
	require.NoError(t, err)
	require.NotNil(t, manager)

	operations.PostgresOwner = ""
	_, err = NewProviderSessionManager(ProviderSessionManagerConfig{
		Repository: repository, Cipher: cipher, Binding: binding,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour, Operations: &operations,
	})
	require.ErrorIs(t, err, ErrProviderSessionInvalid)
}

func completeOperationsFixture() ProviderSessionOperationsConfig {
	return ProviderSessionOperationsConfig{
		Environment: "production", PostgresOwner: "database-team",
		EncryptionKeySource: "kms/provider-sessions", KeyRotationOwner: "security-team",
		ActiveKeyPolicy: "one active write key", RetiredKeyPolicy: "read until migration completes",
		CookiePolicyOwner: "application-security", IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
		StateRetention: time.Hour, SessionRetention: 30 * 24 * time.Hour, TokenRetention: 24 * time.Hour,
		CleanupSchedule: "hourly", CleanupOwner: "platform-team", MonitoringOwner: "platform-oncall",
		OutagePolicy: "fail closed", EmergencyRevocationOwner: "security-oncall",
		EmergencyProcedure: "revoke local sessions then rotate provider credentials",
	}
}

type operationsRepositoryStub struct {
	ProviderSessionRepository
}

type operationsCipherStub struct{}

func (operationsCipherStub) Seal(_ context.Context, _, _ []byte) (TokenEnvelope, error) {
	return TokenEnvelope{}, nil
}

func (operationsCipherStub) Open(_ context.Context, _ TokenEnvelope, _ []byte) ([]byte, error) {
	return nil, nil
}
