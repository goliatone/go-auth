package goadmin

import (
	"context"
	"errors"
	"testing"

	"github.com/goliatone/go-admin/admin"
	auth "github.com/goliatone/go-auth"
)

func TestClaimPermissionResolverMapsConfiguredClaimPermissions(t *testing.T) {
	resolver := NewClaimPermissionResolver(ClaimPermissionConfig{
		PermissionMap: map[string]string{
			"reports:publish": "admin.reports.publish",
		},
	})
	ctx := auth.WithClaimsContext(context.Background(), &auth.JWTClaims{
		UID: "user-1",
		Metadata: map[string]any{
			"permissions": []any{"reports:publish", "unmapped:permission"},
		},
	})

	perms, err := resolver.ResolvePermissions(ctx)
	if err != nil {
		t.Fatalf("ResolvePermissions: %v", err)
	}
	if len(perms) != 1 || perms[0] != "admin.reports.publish" {
		t.Fatalf("unexpected permissions: %#v", perms)
	}

	authorizer := admin.NewGoAuthAuthorizer(admin.GoAuthAuthorizerConfig{
		ResolvePermissions: resolver.ResolvePermissions,
	})
	if !authorizer.Can(ctx, "admin.reports.publish", "") {
		t.Fatal("expected mapped custom permission to be allowed")
	}
	if authorizer.Can(ctx, "admin.reports.archive", "") {
		t.Fatal("expected unmapped custom permission to be denied")
	}
}

func TestClaimPermissionResolverMapsRolesAndGroups(t *testing.T) {
	resolver := NewClaimPermissionResolver(ClaimPermissionConfig{
		RolePermissions: map[string][]string{
			"sso-admin": {"admin.users.invite"},
		},
		GroupPermissions: map[string][]string{
			"finance": {"admin.billing.approve"},
		},
	})
	ctx := auth.WithClaimsContext(context.Background(), &auth.JWTClaims{
		UID: "user-1",
		Metadata: map[string]any{
			"roles":  []string{"sso-admin"},
			"groups": "finance",
		},
	})

	perms, err := resolver.ResolvePermissions(ctx)
	if err != nil {
		t.Fatalf("ResolvePermissions: %v", err)
	}
	want := map[string]bool{"admin.billing.approve": true, "admin.users.invite": true}
	for _, perm := range perms {
		delete(want, perm)
	}
	if len(want) != 0 {
		t.Fatalf("missing permissions: %#v from %#v", want, perms)
	}
}

func TestCustomAdminPermissionsDenyWithoutResolverMapping(t *testing.T) {
	ctx := auth.WithClaimsContext(context.Background(), &auth.JWTClaims{
		UID:      "user-1",
		UserRole: string(auth.RoleAdmin),
		Metadata: map[string]any{
			"permissions": []string{"admin.reports.publish"},
		},
	})
	authorizer := admin.NewGoAuthAuthorizer(admin.GoAuthAuthorizerConfig{})
	if authorizer.Can(ctx, "admin.reports.publish", "") {
		t.Fatal("expected custom permission to be denied without resolver")
	}
}

func TestSSOMetadataFromContextExposesTenantAndOrganization(t *testing.T) {
	ctx := auth.WithClaimsContext(context.Background(), &auth.JWTClaims{
		UID: "user-1",
		Metadata: map[string]any{
			"tenant_id":       "tenant-1",
			"organization_id": "org-1",
		},
	})

	metadata := SSOMetadataFromContext(ctx)
	if metadata["tenant_id"] != "tenant-1" || metadata["organization_id"] != "org-1" {
		t.Fatalf("unexpected metadata: %#v", metadata)
	}
}

func TestComposePermissionResolversCombinesIdPAndLocalPolicy(t *testing.T) {
	resolver := ComposePermissionResolvers(
		func(context.Context) ([]string, error) { return []string{"admin.reports.publish"}, nil },
		func(context.Context) ([]string, error) { return []string{"admin.billing.approve"}, nil },
	)

	perms, err := resolver(context.Background())
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	want := map[string]bool{"admin.billing.approve": true, "admin.reports.publish": true}
	for _, perm := range perms {
		delete(want, perm)
	}
	if len(want) != 0 {
		t.Fatalf("missing composed permissions: %#v from %#v", want, perms)
	}
}

func TestComposePermissionResolversReturnsFailureForDeny(t *testing.T) {
	resolver := ComposePermissionResolvers(
		func(context.Context) ([]string, error) { return []string{"admin.reports.publish"}, nil },
		func(context.Context) ([]string, error) { return nil, errors.New("local policy unavailable") },
	)
	authorizer := admin.NewGoAuthAuthorizer(admin.GoAuthAuthorizerConfig{
		ResolvePermissions: resolver,
	})
	ctx := auth.WithClaimsContext(context.Background(), &auth.JWTClaims{UID: "user-1"})

	if authorizer.Can(ctx, "admin.reports.publish", "") {
		t.Fatal("expected resolver failure to deny custom permission")
	}
}
