package main

import (
	"context"
	"testing"

	"github.com/goliatone/go-admin/admin"
)

type fixedIdentityCounter struct {
	count int
	err   error
}

func (c fixedIdentityCounter) CountProviderIdentities(context.Context, string) (int, error) {
	return c.count, c.err
}

func TestLinkedIdentityProviderReturnsTypedCanonicalPayload(t *testing.T) {
	spec := linkedIdentityProvider(fixedIdentityCounter{count: 7}, "admin.dashboard.main")
	payload, err := spec.Handler(admin.AdminContext{Context: context.Background()}, spec.DefaultConfig)
	if err != nil {
		t.Fatalf("widget handler: %v", err)
	}
	value, ok := payload.Value().(admin.UserStatsWidgetPayload)
	if !ok {
		t.Fatalf("payload type = %T", payload.Value())
	}
	if value.Title != "Supabase linked identities" || value.Metric != "linked_identities" || value.Value != 7 {
		t.Fatalf("payload = %#v", value)
	}
}

func TestLinkedIdentityProviderRejectsUnknownConfig(t *testing.T) {
	spec := linkedIdentityProvider(fixedIdentityCounter{}, "admin.dashboard.main")
	_, err := spec.Handler(
		admin.AdminContext{Context: context.Background()},
		map[string]any{"unexpected": true},
	)
	if err == nil {
		t.Fatal("expected strict widget config error")
	}
}

func TestSupabaseActionsUseSafeReadOnlyRoutes(t *testing.T) {
	spec := supabaseActionsProvider("admin.dashboard.sidebar")
	payload, err := spec.Handler(admin.AdminContext{Context: context.Background()}, nil)
	if err != nil {
		t.Fatalf("widget handler: %v", err)
	}
	value, ok := payload.Value().(admin.QuickActionsWidgetPayload)
	if !ok {
		t.Fatalf("payload type = %T", payload.Value())
	}
	if len(value.Actions) != 2 {
		t.Fatalf("actions = %#v", value.Actions)
	}
	for _, action := range value.Actions {
		if action.Method != "GET" {
			t.Fatalf("unsafe dashboard action = %#v", action)
		}
	}
}
