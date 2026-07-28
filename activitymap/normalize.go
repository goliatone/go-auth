package activitymap

import (
	"maps"
	"strings"
	"time"

	auth "github.com/goliatone/go-auth"
)

const (
	// MetadataKeyActorType stores the actor type derived from auth.ActorRef.Type.
	MetadataKeyActorType = "actor_type"
	// MetadataKeyFromStatus stores the source user status for lifecycle transitions.
	MetadataKeyFromStatus = "from_status"
	// MetadataKeyToStatus stores the target user status for lifecycle transitions.
	MetadataKeyToStatus = "to_status"
)

const (
	defaultChannel    = "auth"
	defaultObjectType = "user"
	defaultActorID    = "system"
)

// Normalized is a transport-agnostic activity shape for downstream systems.
type Normalized struct {
	ActorID    string         `json:"actor_id"`
	Verb       string         `json:"verb"`
	ObjectType string         `json:"object_type,omitempty"`
	ObjectID   string         `json:"object_id,omitempty"`
	Channel    string         `json:"channel,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	OccurredAt time.Time      `json:"occurred_at"`
}

// Option customizes normalization behavior.
type Option func(*normalizeOptions)

type normalizeOptions struct {
	channel          string
	objectType       string
	actorFallback    string
	objectIDResolver func(auth.ActivityEvent) string
}

// Normalize converts an auth.ActivityEvent into a generic normalized shape.
func Normalize(event auth.ActivityEvent, opts ...Option) Normalized {
	options := defaultNormalizeOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	actorID := firstNonEmpty(
		strings.TrimSpace(event.Actor.ID),
		strings.TrimSpace(event.UserID),
		strings.TrimSpace(options.actorFallback),
	)

	objectID := resolveObjectID(event, options.objectIDResolver)
	providerSecurity := auth.IsProviderLifecycleActivity(event.EventType) ||
		auth.IsProviderSessionActivity(event.EventType)
	if providerSecurity {
		actorID = string(auth.EnsureProviderAuditFingerprint(actorID))
		objectID = string(auth.EnsureProviderAuditFingerprint(objectID))
	}
	occurredAt := event.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}

	return Normalized{
		ActorID:    actorID,
		Verb:       string(event.EventType),
		ObjectType: strings.TrimSpace(options.objectType),
		ObjectID:   objectID,
		Channel:    strings.TrimSpace(options.channel),
		Metadata:   normalizeMetadata(event),
		OccurredAt: occurredAt,
	}
}

// WithDefaultChannel sets the default channel for normalized records.
func WithDefaultChannel(channel string) Option {
	return func(opts *normalizeOptions) {
		if opts == nil {
			return
		}
		opts.channel = strings.TrimSpace(channel)
	}
}

// WithDefaultObjectType sets the default object type for normalized records.
func WithDefaultObjectType(objectType string) Option {
	return func(opts *normalizeOptions) {
		if opts == nil {
			return
		}
		opts.objectType = strings.TrimSpace(objectType)
	}
}

// WithObjectIDResolver overrides object-id extraction from ActivityEvent.
func WithObjectIDResolver(resolver func(auth.ActivityEvent) string) Option {
	return func(opts *normalizeOptions) {
		if opts == nil {
			return
		}
		opts.objectIDResolver = resolver
	}
}

// WithActorFallback sets the final actor-id fallback when actor/user ids are empty.
func WithActorFallback(actorID string) Option {
	return func(opts *normalizeOptions) {
		if opts == nil {
			return
		}
		opts.actorFallback = strings.TrimSpace(actorID)
	}
}

func defaultNormalizeOptions() normalizeOptions {
	return normalizeOptions{
		channel:       defaultChannel,
		objectType:    defaultObjectType,
		actorFallback: defaultActorID,
	}
}

func resolveObjectID(event auth.ActivityEvent, resolver func(auth.ActivityEvent) string) string {
	if resolver != nil {
		return strings.TrimSpace(resolver(event))
	}
	return strings.TrimSpace(event.UserID)
}

func normalizeMetadata(event auth.ActivityEvent) map[string]any {
	metadata := cloneMap(event.Metadata)
	if auth.IsProviderLifecycleActivity(event.EventType) {
		metadata = providerLifecycleMetadata(metadata)
	} else if auth.IsProviderSessionActivity(event.EventType) {
		metadata = providerSessionMetadata(metadata)
	}

	if actorType := strings.TrimSpace(event.Actor.Type); actorType != "" {
		if auth.IsProviderLifecycleActivity(event.EventType) ||
			auth.IsProviderSessionActivity(event.EventType) {
			actorType = string(auth.EnsureProviderAuditFingerprint(actorType))
		}
		if metadata == nil {
			metadata = map[string]any{}
		}
		if _, exists := metadata[MetadataKeyActorType]; !exists {
			metadata[MetadataKeyActorType] = actorType
		}
	}

	if event.FromStatus != "" {
		if metadata == nil {
			metadata = map[string]any{}
		}
		metadata[MetadataKeyFromStatus] = string(event.FromStatus)
	}

	if event.ToStatus != "" {
		if metadata == nil {
			metadata = map[string]any{}
		}
		metadata[MetadataKeyToStatus] = string(event.ToStatus)
	}

	return metadata
}

var providerLifecycleMetadataKeys = map[string]struct{}{
	"operation_id": {}, "action": {}, "result": {}, "reason": {},
	"request_id": {}, "provider_request_id": {}, "provider_session_id": {},
	"environment": {}, "target_provider": {}, "target_subject": {},
	"target_object": {}, "session_effect": {}, "retryable": {},
	"residual_expires_at": {},
}

func providerLifecycleMetadata(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]any, len(providerLifecycleMetadataKeys))
	for key, value := range input {
		if _, allowed := providerLifecycleMetadataKeys[key]; !allowed {
			continue
		}
		switch typed := value.(type) {
		case string:
			output[key] = string(auth.EnsureProviderAuditFingerprint(typed))
		case auth.ProviderAuditFingerprint:
			output[key] = string(typed)
		case bool, time.Time, auth.ProviderOperationAction,
			auth.ProviderOperationStatus, auth.ProviderSessionEffect:
			output[key] = value
		}
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

var providerSessionMetadataKeys = map[string]struct{}{
	"local_session_id": {}, "provider": {}, "application_id": {}, "environment": {},
	"status": {}, "token_revision": {}, "result": {}, "reason_code": {},
	"reason_fingerprint": {}, "remote_status": {}, "remote_retryable": {},
	"local_only": {}, "target": {}, "lifecycle_generation": {},
}

func providerSessionMetadata(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]any, len(providerSessionMetadataKeys))
	for key, value := range input {
		if _, allowed := providerSessionMetadataKeys[key]; !allowed {
			continue
		}
		switch key {
		case "local_session_id", "provider", "application_id", "environment", "target", "reason_fingerprint":
			switch typed := value.(type) {
			case string:
				output[key] = string(auth.EnsureProviderAuditFingerprint(typed))
			case auth.ProviderAuditFingerprint:
				output[key] = string(typed)
			}
		case "result":
			if typed, ok := value.(string); ok &&
				(typed == "succeeded" || typed == "failed" || typed == "reauthentication_required") {
				output[key] = typed
			}
		case "status":
			if typed, ok := value.(auth.ProviderSessionStatus); ok && providerSessionStatusValid(typed) {
				output[key] = typed
			}
		case "reason_code":
			if typed, ok := value.(auth.ProviderSessionReasonCode); ok && typed.Valid() {
				output[key] = typed
			}
		case "remote_status":
			if typed, ok := value.(auth.ProviderRemoteRevocationStatus); ok && providerRemoteStatusValid(typed) {
				output[key] = typed
			}
		case "token_revision", "lifecycle_generation":
			switch typed := value.(type) {
			case int:
				if typed >= 0 {
					output[key] = typed
				}
			case int64:
				if typed >= 0 {
					output[key] = typed
				}
			}
		case "remote_retryable", "local_only":
			if typed, ok := value.(bool); ok {
				output[key] = typed
			}
		}
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

func providerSessionStatusValid(status auth.ProviderSessionStatus) bool {
	switch status {
	case auth.ProviderSessionAvailable, auth.ProviderSessionRefreshing,
		auth.ProviderSessionUncertain, auth.ProviderSessionRevoked,
		auth.ProviderSessionExpired:
		return true
	default:
		return false
	}
}

func providerRemoteStatusValid(status auth.ProviderRemoteRevocationStatus) bool {
	switch status {
	case auth.ProviderRemoteRevocationPending, auth.ProviderRemoteRevocationSucceeded,
		auth.ProviderRemoteRevocationFailed, auth.ProviderRemoteRevocationUnsupported:
		return true
	default:
		return false
	}
}

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	maps.Copy(out, in)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
