package auth

import "testing"

func TestEnsureIdentityActivePreservesStatusUnawareIdentityCompatibility(t *testing.T) {
	status, err := EnsureIdentityActive(statusUnawareIdentity{id: "legacy-user"})
	if err != nil {
		t.Fatalf("legacy identity was rejected: %v", err)
	}
	if status != "" {
		t.Fatalf("legacy identity unexpectedly reported status %q", status)
	}
}

type statusUnawareIdentity struct {
	id string
}

func (identity statusUnawareIdentity) ID() string      { return identity.id }
func (statusUnawareIdentity) Username() string         { return "legacy" }
func (statusUnawareIdentity) Email() string            { return "legacy@example.com" }
func (statusUnawareIdentity) Role() string             { return string(RoleMember) }
func (statusUnawareIdentity) Metadata() map[string]any { return nil }
