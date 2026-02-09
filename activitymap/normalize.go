package activitymap

import (
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

	if actorType := strings.TrimSpace(event.Actor.Type); actorType != "" {
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

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
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
