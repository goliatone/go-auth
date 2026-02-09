package activitymap_test

import (
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/activitymap"
)

func TestNormalizeDefaults(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 1, 10, 9, 30, 0, 0, time.UTC)
	event := auth.ActivityEvent{
		EventType:  auth.ActivityEventUserStatusChanged,
		Actor:      auth.ActorRef{ID: "admin-42", Type: "admin"},
		UserID:     "user-100",
		FromStatus: auth.UserStatusActive,
		ToStatus:   auth.UserStatusSuspended,
		Metadata: map[string]any{
			"ticket": "SEC-204",
		},
		OccurredAt: ts,
	}

	out := activitymap.Normalize(event)

	if out.ActorID != "admin-42" {
		t.Fatalf("expected actor_id admin-42, got %q", out.ActorID)
	}
	if out.Verb != string(auth.ActivityEventUserStatusChanged) {
		t.Fatalf("expected verb %q, got %q", auth.ActivityEventUserStatusChanged, out.Verb)
	}
	if out.ObjectType != "user" {
		t.Fatalf("expected object_type user, got %q", out.ObjectType)
	}
	if out.ObjectID != "user-100" {
		t.Fatalf("expected object_id user-100, got %q", out.ObjectID)
	}
	if out.Channel != "auth" {
		t.Fatalf("expected channel auth, got %q", out.Channel)
	}
	if !out.OccurredAt.Equal(ts) {
		t.Fatalf("expected occurred_at %v, got %v", ts, out.OccurredAt)
	}

	if out.Metadata["ticket"] != "SEC-204" {
		t.Fatalf("expected metadata ticket SEC-204, got %#v", out.Metadata["ticket"])
	}
	if out.Metadata[activitymap.MetadataKeyActorType] != "admin" {
		t.Fatalf("expected metadata actor_type admin, got %#v", out.Metadata[activitymap.MetadataKeyActorType])
	}
	if out.Metadata[activitymap.MetadataKeyFromStatus] != string(auth.UserStatusActive) {
		t.Fatalf("expected metadata from_status active, got %#v", out.Metadata[activitymap.MetadataKeyFromStatus])
	}
	if out.Metadata[activitymap.MetadataKeyToStatus] != string(auth.UserStatusSuspended) {
		t.Fatalf("expected metadata to_status suspended, got %#v", out.Metadata[activitymap.MetadataKeyToStatus])
	}

	if len(event.Metadata) != 1 {
		t.Fatalf("expected source metadata to remain unchanged, got %+v", event.Metadata)
	}
}

func TestNormalizeOptionOverrides(t *testing.T) {
	t.Parallel()

	event := auth.ActivityEvent{
		EventType: auth.ActivityEventPasswordResetSuccess,
		Actor:     auth.ActorRef{Type: "user"},
		UserID:    "user-200",
		Metadata: map[string]any{
			"password_reset_id":              "reset-1",
			activitymap.MetadataKeyActorType: "existing",
		},
	}

	out := activitymap.Normalize(
		event,
		activitymap.WithDefaultChannel("security"),
		activitymap.WithDefaultObjectType("account"),
		activitymap.WithObjectIDResolver(func(e auth.ActivityEvent) string {
			if v, ok := e.Metadata["password_reset_id"].(string); ok {
				return v
			}
			return ""
		}),
	)

	if out.Channel != "security" {
		t.Fatalf("expected channel security, got %q", out.Channel)
	}
	if out.ObjectType != "account" {
		t.Fatalf("expected object_type account, got %q", out.ObjectType)
	}
	if out.ObjectID != "reset-1" {
		t.Fatalf("expected object_id reset-1, got %q", out.ObjectID)
	}
	if out.Metadata[activitymap.MetadataKeyActorType] != "existing" {
		t.Fatalf("expected existing actor_type preserved, got %#v", out.Metadata[activitymap.MetadataKeyActorType])
	}
	if out.OccurredAt.IsZero() {
		t.Fatalf("expected occurred_at to be set when input is zero")
	}
}

func TestNormalizeActorFallbackChain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		event  auth.ActivityEvent
		opts   []activitymap.Option
		expect string
	}{
		{
			name:   "uses actor id when present",
			event:  auth.ActivityEvent{Actor: auth.ActorRef{ID: "actor-1"}, UserID: "user-1"},
			expect: "actor-1",
		},
		{
			name:   "uses user id when actor id missing",
			event:  auth.ActivityEvent{Actor: auth.ActorRef{ID: ""}, UserID: "user-2"},
			expect: "user-2",
		},
		{
			name:   "uses default fallback when actor and user missing",
			event:  auth.ActivityEvent{},
			expect: "system",
		},
		{
			name:   "uses configured fallback when actor and user missing",
			event:  auth.ActivityEvent{},
			opts:   []activitymap.Option{activitymap.WithActorFallback("job")},
			expect: "job",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := activitymap.Normalize(tc.event, tc.opts...)
			if out.ActorID != tc.expect {
				t.Fatalf("expected actor_id %q, got %q", tc.expect, out.ActorID)
			}
		})
	}
}
