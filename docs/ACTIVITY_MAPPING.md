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

`Normalize` clones `event.Metadata` and never mutates the source event map.

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
