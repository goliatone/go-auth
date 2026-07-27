package auth

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokenTargetRegistryIsImmutableAndCapabilityBound(t *testing.T) {
	t.Parallel()
	capability, err := NewTokenTargetCapability()
	require.NoError(t, err)
	target := TokenTarget{
		Name: "business-data", Provider: "oidc", Issuer: "https://issuer.example.com/",
		ClientID: "client-1", Audience: "business-api", RequiredScopes: []string{"read"},
		TelemetryName: "business_data", RequirePolicy: true, Capability: capability,
	}
	registry, err := NewTokenTargetRegistry(target)
	require.NoError(t, err)
	target.RequiredScopes[0] = "admin"

	resolved, err := registry.Resolve("business-data", capability)
	require.NoError(t, err)
	require.Equal(t, []string{"read"}, resolved.RequiredScopes)
	require.Equal(t, "https://issuer.example.com", resolved.Issuer)

	wrongCapability, err := NewTokenTargetCapability()
	require.NoError(t, err)
	_, err = registry.Resolve("business-data", wrongCapability)
	require.ErrorIs(t, err, ErrProviderTokenTarget)
	_, err = registry.Resolve("unknown", capability)
	require.ErrorIs(t, err, ErrProviderTokenTarget)
}

func TestTokenTargetRegistryRejectsDuplicatesAndIncompleteBindings(t *testing.T) {
	t.Parallel()
	capability, err := NewTokenTargetCapability()
	require.NoError(t, err)
	target := TokenTarget{
		Name: "target", Provider: "oidc", Issuer: "https://issuer.example.com",
		ClientID: "client", Audience: "api", TelemetryName: "target", Capability: capability,
	}
	_, err = NewTokenTargetRegistry(target, target)
	require.ErrorIs(t, err, ErrProviderTokenTarget)
	target.Audience = ""
	_, err = NewTokenTargetRegistry(target)
	require.ErrorIs(t, err, ErrProviderTokenTarget)
}

func TestTokenTargetCapabilityIsRedacted(t *testing.T) {
	t.Parallel()
	capability, err := NewTokenTargetCapability()
	require.NoError(t, err)
	formatted := fmt.Sprintf("%v %#v", capability, capability)
	require.Contains(t, formatted, redactedSecret)
	require.NotContains(t, formatted, capability.id)
	_, err = json.Marshal(capability)
	require.ErrorIs(t, err, ErrSecretSerialization)
}
