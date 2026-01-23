package goauthadapter

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-featuregate/gate"
)

func TestClaimsFromActorDefaults(t *testing.T) {
	actor := &auth.ActorContext{
		ActorID:        "user-123",
		Subject:        "sub-456",
		Role:           "admin",
		TenantID:       "tenant-1",
		OrganizationID: "org-1",
		ResourceRoles: map[string]string{
			"project": "viewer",
			"org":     "admin",
		},
	}

	claims := ClaimsFromActor(actor)

	if claims.SubjectID != "user-123" {
		t.Fatalf("expected SubjectID to use ActorID, got %q", claims.SubjectID)
	}
	if claims.TenantID != "tenant-1" || claims.OrgID != "org-1" {
		t.Fatalf("unexpected tenant/org: %q/%q", claims.TenantID, claims.OrgID)
	}
	if !reflect.DeepEqual(claims.Roles, []string{"admin"}) {
		t.Fatalf("unexpected roles: %#v", claims.Roles)
	}
	expectedPerms := []string{"org:admin", "project:viewer"}
	if !reflect.DeepEqual(claims.Perms, expectedPerms) {
		t.Fatalf("unexpected perms: %#v", claims.Perms)
	}
}

func TestClaimsProviderClaimsFromContextMissingActor(t *testing.T) {
	provider := NewClaimsProvider(WithActorExtractor(func(context.Context) (*auth.ActorContext, bool) {
		return nil, false
	}))

	claims, err := provider.ClaimsFromContext(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(claims, gate.ActorClaims{}) {
		t.Fatalf("expected empty claims, got %#v", claims)
	}
}

func TestClaimsProviderCustomFormatter(t *testing.T) {
	provider := NewClaimsProvider(
		WithPermissionFormatter(func(resource, role string) string {
			return resource + "." + role
		}),
	)

	actor := &auth.ActorContext{
		ActorID: "user-1",
		ResourceRoles: map[string]string{
			"org": "admin",
		},
	}
	ctx := auth.WithActorContext(context.Background(), actor)

	claims, err := provider.ClaimsFromContext(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(claims.Perms, []string{"org.admin"}) {
		t.Fatalf("unexpected perms: %#v", claims.Perms)
	}
}

func TestPermissionProviderMerge(t *testing.T) {
	provider := NewPermissionProvider()

	actor := &auth.ActorContext{
		ResourceRoles: map[string]string{
			"org": "admin",
		},
	}
	ctx := auth.WithActorContext(context.Background(), actor)
	claims := gate.ActorClaims{Perms: []string{"from-claims"}}

	perms, err := provider.Permissions(ctx, claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []string{"from-claims", "org:admin"}
	if !reflect.DeepEqual(perms, expected) {
		t.Fatalf("unexpected perms: %#v", perms)
	}
}

func TestPermissionProviderCustomResolver(t *testing.T) {
	provider := NewPermissionProvider(WithPermConflictResolver(func(existing, derived []string) []string {
		return derived
	}))

	actor := &auth.ActorContext{
		ResourceRoles: map[string]string{
			"org":     "admin",
			"project": "viewer",
		},
	}
	ctx := auth.WithActorContext(context.Background(), actor)
	claims := gate.ActorClaims{Perms: []string{"from-claims"}}

	perms, err := provider.Permissions(ctx, claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sort.Strings(perms)
	expected := []string{"org:admin", "project:viewer"}
	if !reflect.DeepEqual(perms, expected) {
		t.Fatalf("unexpected perms: %#v", perms)
	}
}

func TestActorRefFromActorUsesStableType(t *testing.T) {
	actor := &auth.ActorContext{
		ActorID: "user-1",
		Subject: "subject-value",
		Role:    "member",
	}

	ref := ActorRefFromActor(actor)

	if ref.Type != defaultActorRefType {
		t.Fatalf("expected actor type %q, got %q", defaultActorRefType, ref.Type)
	}
	if ref.ID != "user-1" || ref.Name != "member" {
		t.Fatalf("unexpected ref: %#v", ref)
	}
}
