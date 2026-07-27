package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
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

func TestDefaultClaimsMapperRejectsUncorrelatedUserInfo(t *testing.T) {
	claims := jwt.MapClaims{"sub": "subject-1"}
	for name, userInfo := range map[string]map[string]any{
		"missing subject": {"email": "person@example.com"},
		"wrong subject":   {"sub": "subject-2", "email": "person@example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := (DefaultClaimsMapper{}).MapClaims(
				context.Background(),
				ProviderConfig{Key: "test"},
				claims,
				userInfo,
			)
			if !errorHasTextCode(err, TextCodeOIDCInvalidIDToken) {
				t.Fatalf("expected invalid ID token error, got %v", err)
			}
		})
	}
}

func TestDefaultClaimsMapperRestrictsUserInfoToProfileClaims(t *testing.T) {
	claims := jwt.MapClaims{
		"sub":             "subject-1",
		"tenant_id":       "trusted-tenant",
		"organization_id": "trusted-org",
		"roles":           []any{"trusted-role"},
		"permissions":     []any{"trusted:permission"},
		"groups":          []any{"trusted-group"},
		"resource_roles":  map[string]any{"trusted": "role"},
	}
	userInfo := map[string]any{
		"sub":             "subject-1",
		"email":           "profile@example.com",
		"tenant_id":       "untrusted-tenant",
		"organization_id": "untrusted-org",
		"roles":           []any{"untrusted-role"},
		"permissions":     []any{"untrusted:permission"},
		"groups":          []any{"untrusted-group"},
		"resource_roles":  map[string]any{"untrusted": "role"},
	}

	identity, mapped, err := (DefaultClaimsMapper{}).MapClaims(
		context.Background(),
		ProviderConfig{Key: "test"},
		claims,
		userInfo,
	)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Email != "profile@example.com" {
		t.Fatalf("profile email was not enriched: %+v", identity)
	}
	if identity.TenantID != "trusted-tenant" || identity.OrganizationID != "trusted-org" {
		t.Fatalf("userinfo supplied tenant authority: %+v", identity)
	}
	if len(identity.Roles) != 1 || identity.Roles[0] != "trusted-role" ||
		len(identity.Permissions) != 1 || identity.Permissions[0] != "trusted:permission" {
		t.Fatalf("userinfo supplied authorization authority: %+v", identity)
	}
	if identity.ResourceRoles["trusted"] != "role" || identity.ResourceRoles["untrusted"] != "" {
		t.Fatalf("userinfo supplied resource roles: %+v", identity.ResourceRoles)
	}
	if groups, _ := mapped.Metadata["groups"].([]string); len(groups) != 1 || groups[0] != "trusted-group" {
		t.Fatalf("userinfo supplied group authority: %+v", mapped.Metadata)
	}
}

func TestDefaultMappersBindEmailVerificationToSelectedSource(t *testing.T) {
	claims := jwt.MapClaims{
		"iss":            "https://issuer.example/",
		"sub":            "subject-1",
		"email":          "id-token@example.com",
		"email_verified": true,
	}
	userInfo := map[string]any{
		"sub":   "subject-1",
		"email": "userinfo@example.com",
	}

	legacy, _, err := (DefaultClaimsMapper{}).MapClaims(
		context.Background(),
		ProviderConfig{Key: "test"},
		claims,
		userInfo,
	)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Email != "userinfo@example.com" || legacy.EmailVerified {
		t.Fatalf("legacy mapper mixed email provenance: %+v", legacy)
	}

	principal, err := (DefaultPrincipalMapper{}).MapPrincipal(
		context.Background(),
		ProviderConfig{Key: "test"},
		auth.ValidatedTokenContext{
			Issuer:  "https://issuer.example/",
			Subject: "subject-1",
		},
		nil,
		claims,
		nil,
		userInfo,
	)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Email != "userinfo@example.com" || principal.EmailVerified {
		t.Fatalf("principal mapper mixed email provenance: %+v", principal)
	}
	if principal.Provenance["email"] != ClaimSourceUserInfo {
		t.Fatalf("email provenance = %q, want userinfo", principal.Provenance["email"])
	}
	if _, ok := principal.Provenance["email_verified"]; ok {
		t.Fatalf("verification provenance should be absent: %+v", principal.Provenance)
	}
}
