package activitymap_test

import (
	"encoding/json"
	"strings"
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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := activitymap.Normalize(tc.event, tc.opts...)
			if out.ActorID != tc.expect {
				t.Fatalf("expected actor_id %q, got %q", tc.expect, out.ActorID)
			}
		})
	}
}

func TestNormalizeSSOEvents(t *testing.T) {
	t.Parallel()

	events := []auth.ActivityEventType{
		auth.ActivityEventSSOLoginSuccess,
		auth.ActivityEventSSOLoginFailure,
		auth.ActivityEventSSOLinkAutomatic,
		auth.ActivityEventSSOLinkManual,
		auth.ActivityEventSSOLinkRejected,
		auth.ActivityEventSSOUnlink,
		auth.ActivityEventSSOLogout,
	}

	for _, eventType := range events {
		t.Run(string(eventType), func(t *testing.T) {
			t.Parallel()

			out := activitymap.Normalize(auth.ActivityEvent{
				EventType: eventType,
				UserID:    "user-1",
				Metadata:  map[string]any{"provider": "oidc"},
			})
			if out.Verb != string(eventType) {
				t.Fatalf("expected verb %q, got %q", eventType, out.Verb)
			}
			if out.Metadata["provider"] != "oidc" {
				t.Fatalf("expected provider metadata, got %+v", out.Metadata)
			}
		})
	}
}

func TestNormalizeProviderLifecycleEventFiltersSensitiveMetadata(t *testing.T) {
	t.Parallel()

	event := auth.ActivityEvent{
		EventType: auth.ActivityEventProviderAuthApprove,
		Actor:     auth.ActorRef{ID: "admin-42", Type: "admin"},
		UserID:    "user-100",
		Metadata: map[string]any{
			"operation_id":    "operation-1",
			"action":          auth.ProviderActionAuthorizationApprove,
			"result":          auth.ProviderOperationSucceeded,
			"reason":          "authorization: bearer private-token",
			"request_id":      "request-1",
			"target_provider": "supabase",
			"provider_session_id": auth.ProviderAuditFingerprint(
				"typed-lifecycle-canary",
			),
			"retryable":          false,
			"authorization_code": "secret-code",
			"refresh_token":      "secret-refresh-token",
			"cookie":             "session=secret",
			"credentials":        map[string]any{"client_secret": "secret"},
		},
	}

	out := activitymap.Normalize(event)
	payload, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal normalized activity: %v", err)
	}
	serialized := strings.ToLower(string(payload))

	expectedReason := string(auth.FingerprintProviderAuditValue("authorization: bearer private-token"))
	if out.Metadata["reason"] != expectedReason {
		t.Fatalf("expected sensitive reason to be fingerprinted, got %#v", out.Metadata["reason"])
	}
	for _, key := range []string{"authorization_code", "refresh_token", "cookie", "credentials"} {
		if _, exists := out.Metadata[key]; exists {
			t.Fatalf("expected metadata key %q to be removed, got %+v", key, out.Metadata)
		}
	}
	for _, secret := range []string{
		"private-token", "secret-code", "secret-refresh-token", "client_secret",
		"typed-lifecycle-canary",
	} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("normalized lifecycle audit contains secret marker %q: %s", secret, serialized)
		}
	}
	if out.Metadata["operation_id"] != string(auth.FingerprintProviderAuditValue("operation-1")) {
		t.Fatalf("expected safe operation correlation, got %+v", out.Metadata)
	}
	if out.Metadata[activitymap.MetadataKeyActorType] != string(auth.FingerprintProviderAuditValue("admin")) {
		t.Fatalf("expected normalized actor type, got %+v", out.Metadata)
	}
	if out.ActorID != string(auth.FingerprintProviderAuditValue("admin-42")) ||
		out.ObjectID != string(auth.FingerprintProviderAuditValue("user-100")) {
		t.Fatalf("expected lifecycle actor/object identifiers to be fingerprinted, got %+v", out)
	}
}

func TestNormalizeProviderSessionEventFiltersAndFingerprintsCanaries(t *testing.T) {
	t.Parallel()

	event := auth.ActivityEvent{
		EventType: auth.ActivityEventProviderSessionRevoked,
		Actor:     auth.ActorRef{ID: "actor-canary", Type: "actor-type-canary"},
		UserID:    "subject-canary",
		Metadata: map[string]any{
			"local_session_id":   "session-canary",
			"provider":           "provider-canary",
			"application_id":     "application-canary",
			"environment":        "environment-canary",
			"status":             auth.ProviderSessionRevoked,
			"token_revision":     int64(2),
			"result":             "failed",
			"reason_code":        auth.ProviderSessionReasonLegacyExternal,
			"reason_fingerprint": auth.ProviderAuditFingerprint("raw-reason-canary"),
			"remote_status":      auth.ProviderRemoteRevocationFailed,
			"refresh_token":      "refresh-secret-canary",
			"reason":             "raw-reason-canary",
			"arbitrary":          map[string]any{"secret": "nested-secret-canary"},
		},
	}

	out := activitymap.Normalize(event)
	payload, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal normalized provider session activity: %v", err)
	}
	serialized := strings.ToLower(string(payload))
	for _, canary := range []string{
		"actor-canary", "actor-type-canary", "subject-canary", "session-canary",
		"provider-canary", "application-canary", "environment-canary",
		"raw-reason-canary", "refresh-secret-canary", "nested-secret-canary",
	} {
		if strings.Contains(serialized, canary) {
			t.Fatalf("normalized provider-session audit contains canary %q: %s", canary, serialized)
		}
	}
	for _, key := range []string{"refresh_token", "reason", "arbitrary"} {
		if _, exists := out.Metadata[key]; exists {
			t.Fatalf("expected provider-session metadata key %q to be removed: %+v", key, out.Metadata)
		}
	}
	if out.Metadata["reason_fingerprint"] !=
		string(auth.FingerprintProviderAuditValue("raw-reason-canary")) {
		t.Fatalf("expected typed raw reason to be fingerprinted: %+v", out.Metadata)
	}
}

func TestNormalizeNonLifecycleEventPreservesExistingMetadataBehavior(t *testing.T) {
	t.Parallel()

	event := auth.ActivityEvent{
		EventType: auth.ActivityEventLoginSuccess,
		UserID:    "user-1",
		Metadata:  map[string]any{"custom": "kept"},
	}

	out := activitymap.Normalize(event)
	if out.Metadata["custom"] != "kept" {
		t.Fatalf("expected non-lifecycle metadata to remain unchanged, got %+v", out.Metadata)
	}
}
