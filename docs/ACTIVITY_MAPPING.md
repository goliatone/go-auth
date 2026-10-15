# Activity Mapping

`go-auth` exposes `activitymap.Normalize` for translating `auth.ActivityEvent`
into a transport-agnostic activity record:

- `actor_id`
- `verb`
- `object_type`
- `object_id`
- `channel`
- `metadata`
- `occurred_at`

## Package

```go
import "github.com/goliatone/go-auth/activitymap"
```

## Defaults

- `channel`: `auth`
- `object_type`: `user`
- `object_id`: `event.UserID`
- `actor_id`: `event.Actor.ID -> event.UserID -> "system"`

## Options

- `activitymap.WithDefaultChannel(string)`
- `activitymap.WithDefaultObjectType(string)`
- `activitymap.WithObjectIDResolver(func(auth.ActivityEvent) string)`
- `activitymap.WithActorFallback(string)`

## Metadata behavior

`Normalize` shallow-clones ordinary event metadata and never mutates the source event
map. Provider-session/lifecycle events use restricted metadata projections and
fingerprint identity fields before output. This normalizer is not a general
secret/PII sanitizer for ordinary events: login events can carry raw unverified
submitted identifiers and provider error text. Apply the host's allowlist,
redaction and retention policy before storing or forwarding ordinary metadata.

For a go-users audit feed, use `go-users/adapter/goauth.NewActivitySink` with a
trusted exact tenant/org scope and anonymous actor UUID, followed by a host-owned
`activity.RecordPolicy`. Failed-login identifier retention requires an explicit
opt-in at both boundaries; attempted input never establishes actor identity.

It also enriches metadata with:

- `actor_type` when `event.Actor.Type` is present and no existing `actor_type`
  key exists.
- `from_status` and `to_status` for lifecycle transition events.

## Example: bridge into an external sink

```go
sink := auth.ActivitySinkFunc(func(ctx context.Context, event auth.ActivityEvent) error {
	normalized := activitymap.Normalize(
		event,
		activitymap.WithDefaultChannel("auth"),
		activitymap.WithDefaultObjectType("user"),
	)

	return externalSink.Record(ctx, ExternalRecord{
		ActorID:    normalized.ActorID,
		Verb:       normalized.Verb,
		ObjectType: normalized.ObjectType,
		ObjectID:   normalized.ObjectID,
		Channel:    normalized.Channel,
		Metadata:   normalized.Metadata,
		OccurredAt: normalized.OccurredAt,
	})
})
```
