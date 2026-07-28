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
		Deployment: ProviderSessionDeploymentProduction,
	})
	require.ErrorIs(t, err, ErrProviderSessionInvalid)

	operations := completeOperationsFixture()
	manager, err := NewProviderSessionManager(ProviderSessionManagerConfig{
		Repository: repository, Cipher: cipher, Binding: binding,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
		Deployment: ProviderSessionDeploymentProduction, Operations: &operations,
	})
	require.NoError(t, err)
	require.NotNil(t, manager)

	operations.PostgresOwner = ""
	_, err = NewProviderSessionManager(ProviderSessionManagerConfig{
		Repository: repository, Cipher: cipher, Binding: binding,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
		Deployment: ProviderSessionDeploymentProduction, Operations: &operations,
	})
	require.ErrorIs(t, err, ErrProviderSessionInvalid)
}

func TestProviderSessionManagerRequiresExplicitDeploymentClass(t *testing.T) {
	t.Parallel()
	_, err := NewProviderSessionManager(ProviderSessionManagerConfig{
		Repository: &operationsRepositoryStub{},
		Cipher:     operationsCipherStub{},
		Binding: ProviderSessionBinding{
			Host: "app.example.com", ApplicationID: "app", Environment: "test",
			Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client",
		},
		IdleLifetime: time.Hour,
		MaxLifetime:  8 * time.Hour,
	})
	require.ErrorIs(t, err, ErrProviderSessionInvalid)
}

func TestProviderSessionDeploymentClassCannotBeBypassedByEnvironmentAlias(t *testing.T) {
	t.Parallel()
	for _, environment := range []string{"live", "prd", "production-us", "arbitrary-blue"} {
		t.Run(environment, func(t *testing.T) {
			binding := ProviderSessionBinding{
				Host: "app.example.com", ApplicationID: "app", Environment: environment,
				Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client",
			}
			_, err := NewProviderSessionManager(ProviderSessionManagerConfig{
				Repository:   &operationsRepositoryStub{},
				Cipher:       operationsCipherStub{},
				Binding:      binding,
				Deployment:   ProviderSessionDeploymentProduction,
				IdleLifetime: time.Hour,
				MaxLifetime:  8 * time.Hour,
			})
			require.ErrorIs(t, err, ErrProviderSessionInvalid)

			operations := completeOperationsFixture()
			operations.Environment = environment
			manager, err := NewProviderSessionManager(ProviderSessionManagerConfig{
				Repository:   &operationsRepositoryStub{},
				Cipher:       operationsCipherStub{},
				Binding:      binding,
				Deployment:   ProviderSessionDeploymentProduction,
				Operations:   &operations,
				IdleLifetime: time.Hour,
				MaxLifetime:  8 * time.Hour,
			})
			require.NoError(t, err)
			require.NotNil(t, manager)
		})
	}
}

func TestProviderSessionLegacyProductionNamesRemainAdditionalGuard(t *testing.T) {
	t.Parallel()
	for _, environment := range []string{"prod", "production"} {
		binding := ProviderSessionBinding{
			Host: "app.example.com", ApplicationID: "app", Environment: environment,
			Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client",
		}
		_, err := NewProviderSessionManager(ProviderSessionManagerConfig{
			Repository:   &operationsRepositoryStub{},
			Cipher:       operationsCipherStub{},
			Binding:      binding,
			Deployment:   ProviderSessionDeploymentDevelopment,
			IdleLifetime: time.Hour,
			MaxLifetime:  8 * time.Hour,
		})
		require.ErrorIs(t, err, ErrProviderSessionInvalid)
	}
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
