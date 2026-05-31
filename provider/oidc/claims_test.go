package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestDefaultClaimsMapperMapsStandardAndProviderClaims(t *testing.T) {
	claims := jwt.MapClaims{
		"iss":             "https://issuer.example/",
		"sub":             "subject-1",
		"aud":             "api://default",
		"exp":             time.Now().Add(time.Hour).Unix(),
		"iat":             time.Now().Add(-time.Minute).Unix(),
		"email":           "person@example.com",
		"email_verified":  true,
		"groups":          []any{"engineering", "admin"},
		"roles":           []any{"admin"},
		"permissions":     []any{"users:read", "users:write"},
		"resource_roles":  map[string]any{"users": "admin"},
		"tenant_id":       "tenant-1",
		"organization_id": "org-1",
	}

	identity, mapped, err := (DefaultClaimsMapper{}).MapClaims(context.Background(), ProviderConfig{Key: "test"}, claims, nil)
	if err != nil {
		t.Fatalf("MapClaims returned error: %v", err)
	}
	if identity.Subject != "subject-1" || identity.Email != "person@example.com" || !identity.EmailVerified {
		t.Fatalf("identity basic claims not mapped: %+v", identity)
	}
	if identity.TenantID != "tenant-1" || identity.OrganizationID != "org-1" {
		t.Fatalf("tenant/org not mapped: %+v", identity)
	}
	if len(identity.Roles) != 1 || identity.Roles[0] != "admin" {
		t.Fatalf("roles not mapped: %+v", identity.Roles)
	}
	if len(identity.Permissions) != 2 || identity.Permissions[1] != "users:write" {
		t.Fatalf("permissions not mapped: %+v", identity.Permissions)
	}
	if identity.ResourceRoles["users"] != "admin" || mapped.Resources["users"] != "admin" {
		t.Fatalf("resource roles not mapped: identity=%+v claims=%+v", identity.ResourceRoles, mapped.Resources)
	}
	if mapped.Metadata["tenant_id"] != "tenant-1" || mapped.Metadata["organization_id"] != "org-1" {
		t.Fatalf("metadata not enriched: %+v", mapped.Metadata)
	}
}

func TestDefaultClaimsMapperUsesConfiguredClaimKeys(t *testing.T) {
	claims := jwt.MapClaims{
		"sub":       "subject-1",
		"org":       "org-2",
		"tenant":    "tenant-2",
		"app_roles": []any{"owner"},
	}
	provider := ProviderConfig{
		Key: "custom",
		ClaimKeys: ClaimKeys{
			OrganizationID: []string{"org"},
			TenantID:       []string{"tenant"},
			Roles:          []string{"app_roles"},
		},
	}

	identity, _, err := (DefaultClaimsMapper{}).MapClaims(context.Background(), provider, claims, nil)
	if err != nil {
		t.Fatalf("MapClaims returned error: %v", err)
	}
	if identity.OrganizationID != "org-2" || identity.TenantID != "tenant-2" {
		t.Fatalf("configured string claims not mapped: %+v", identity)
	}
	if len(identity.Roles) != 1 || identity.Roles[0] != "owner" {
		t.Fatalf("configured roles not mapped: %+v", identity.Roles)
	}
}

func TestDefaultClaimsMapperMapsOrgIDFallback(t *testing.T) {
	identity, _, err := (DefaultClaimsMapper{}).MapClaims(context.Background(), ProviderConfig{Key: "test"}, jwt.MapClaims{
		"sub":    "subject-1",
		"org_id": "org-fallback",
	}, nil)
	if err != nil {
		t.Fatalf("MapClaims returned error: %v", err)
	}
	if identity.OrganizationID != "org-fallback" {
		t.Fatalf("org_id fallback not mapped: %+v", identity)
	}
}
