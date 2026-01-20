package extensions

import (
	"context"
	"database/sql"
	"encoding/json"

	auth "github.com/goliatone/go-auth"
	"github.com/google/uuid"
)

// TenantContext represents the metadata a downstream service wants to inject.
type TenantContext struct {
	TenantID      string
	ResourceRoles map[string]string
}

// TenantLookup resolves tenant metadata for a user.
type TenantLookup func(ctx context.Context, userID string) (TenantContext, error)

const insertAuditSQL = `
INSERT INTO user_activity (
	event_type,
	actor_id,
	actor_type,
	user_id,
	from_status,
	to_status,
	metadata,
	occurred_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8);
`

// NewAuditSink persists lifecycle and authentication events into an audit table.
func NewAuditSink(db *sql.DB) auth.ActivitySink {
	return auth.ActivitySinkFunc(func(ctx context.Context, event auth.ActivityEvent) error {
		if db == nil {
			return nil
		}

		metadata, err := json.Marshal(event.Metadata)
		if err != nil {
			return err
		}

		_, err = db.ExecContext(
			ctx,
			insertAuditSQL,
			event.EventType,
			event.Actor.ID,
			event.Actor.Type,
			event.UserID,
			event.FromStatus,
			event.ToStatus,
			metadata,
			event.OccurredAt,
		)
		return err
	})
}

// MultiTenantClaimsDecorator injects tenant metadata / resource roles into JWTs.
func MultiTenantClaimsDecorator(lookup TenantLookup) auth.ClaimsDecorator {
	return auth.ClaimsDecoratorFunc(func(ctx context.Context, identity auth.Identity, claims *auth.JWTClaims) error {
		if lookup == nil || identity == nil || claims == nil {
			return nil
		}

		tenant, err := lookup(ctx, identity.ID())
		if err != nil {
			return err
		}

		if tenant.TenantID != "" {
			if claims.Metadata == nil {
				claims.Metadata = make(map[string]any)
			}
			claims.Metadata["tenant_id"] = tenant.TenantID
		}

		if len(tenant.ResourceRoles) > 0 {
			if claims.Resources == nil {
				claims.Resources = make(map[string]string, len(tenant.ResourceRoles))
			}
			for resource, role := range tenant.ResourceRoles {
				claims.Resources[resource] = role
			}
		}

		return nil
	})
}

// ExampleLifecycleExtensions demonstrates wiring the state machine, ActivitySink, and ClaimsDecorator.
func ExampleLifecycleExtensions() {
	var (
		ctx    = context.Background()
		db     *sql.DB
		users  auth.Users
		auther *auth.Auther
	)

	auditSink := NewAuditSink(db)

	stateMachine := auth.NewUserStateMachine(
		users,
		auth.WithStateMachineActivitySink(auditSink),
	)

	_, _ = stateMachine.Transition(
		ctx,
		auth.ActorRef{ID: "admin-42", Type: "admin"},
		&auth.User{ID: uuid.New(), Status: auth.UserStatusActive},
		auth.UserStatusSuspended,
		auth.WithTransitionReason("manual review"),
		auth.WithTransitionMetadata(map[string]any{
			"ticket": "SEC-204",
		}),
	)

	decorator := MultiTenantClaimsDecorator(func(ctx context.Context, userID string) (TenantContext, error) {
		return TenantContext{
			TenantID: "tenant-" + userID,
			ResourceRoles: map[string]string{
				"admin:dashboard": "viewer",
				"billing:portal":  "editor",
			},
		}, nil
	})

	_ = auther.
		WithActivitySink(auditSink).
		WithClaimsDecorator(decorator)
}
