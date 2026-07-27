package supabase

import (
	"context"
	"errors"
	"time"

	auth "github.com/goliatone/go-auth"
)

func (c *Client) recordLifecycleActivity(
	ctx context.Context,
	operation auth.AuthorizedOperationContext,
	outcome auth.ProviderOperationOutcome,
	operationErr error,
) {
	if c == nil || c.activitySink == nil {
		return
	}
	if outcome.Validate() != nil {
		outcome.Status = auth.ProviderOperationFailed
		outcome.Retryable = false
	}
	event, err := auth.NewProviderLifecycleActivityEvent(
		operation,
		outcome,
		time.Now().UTC(),
	)
	if err == nil {
		err = c.activitySink.Record(ctx, event)
	}
	if err != nil && c.auditErrorHandler != nil {
		c.auditErrorHandler(ctx, errors.Join(operationErr, err))
	}
}

func (a *AdminClient) recordLifecycleActivity(
	ctx context.Context,
	operation auth.AuthorizedOperationContext,
	outcome auth.ProviderOperationOutcome,
	operationErr error,
) {
	if a == nil {
		return
	}
	a.client.recordLifecycleActivity(ctx, operation, outcome, operationErr)
}

func (s *AuthorizationService) recordLifecycleActivity(
	ctx context.Context,
	operation auth.AuthorizedOperationContext,
	outcome auth.ProviderOperationOutcome,
	operationErr error,
) {
	if s == nil {
		return
	}
	s.client.recordLifecycleActivity(ctx, operation, outcome, operationErr)
}
