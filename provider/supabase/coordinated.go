package supabase

import (
	"context"
	"strconv"

	auth "github.com/goliatone/go-auth"
)

type accountLifecycleExecutor struct {
	admin   *AdminClient
	request auth.AccountLifecycleRequest
	action  auth.ProviderOperationAction
}

func (e accountLifecycleExecutor) ExecuteProviderOperation(
	ctx context.Context,
	_ auth.AuthorizedOperationContext,
) (auth.ProviderOperationOutcome, error) {
	var result auth.AccountStateResult
	var err error
	switch e.action {
	case auth.ProviderActionSuspend:
		result, err = e.admin.Suspend(ctx, e.request)
	case auth.ProviderActionActivate:
		result, err = e.admin.Activate(ctx, e.request)
	default:
		return auth.ProviderOperationOutcome{}, auth.ErrProviderOperationUnsupported
	}
	return result.ProviderOperationOutcome, err
}

func (e accountLifecycleExecutor) ExecuteCoordinatedProviderOperation(
	ctx context.Context,
	_ auth.AuthorizedOperationContext,
	permit auth.LifecycleExecutionPermit,
) (auth.ProviderOperationOutcome, error) {
	var result auth.AccountStateResult
	var err error
	switch e.action {
	case auth.ProviderActionSuspend:
		result, err = e.admin.SuspendCoordinated(ctx, e.request, permit)
	case auth.ProviderActionActivate:
		result, err = e.admin.ActivateCoordinated(ctx, e.request, permit)
	default:
		return auth.ProviderOperationOutcome{}, auth.ErrProviderOperationUnsupported
	}
	return result.ProviderOperationOutcome, err
}

func (a *AdminClient) SuspendExecutor(
	request auth.AccountLifecycleRequest,
) auth.ProviderOperationExecutor {
	return accountLifecycleExecutor{admin: a, request: request, action: auth.ProviderActionSuspend}
}

func (a *AdminClient) ActivateExecutor(
	request auth.AccountLifecycleRequest,
) auth.ProviderOperationExecutor {
	return accountLifecycleExecutor{admin: a, request: request, action: auth.ProviderActionActivate}
}

type factorRemoveExecutor struct {
	admin   *AdminClient
	request auth.FactorRemoveRequest
}

func (e factorRemoveExecutor) ExecuteProviderOperation(
	ctx context.Context,
	_ auth.AuthorizedOperationContext,
) (auth.ProviderOperationOutcome, error) {
	return e.admin.RemoveFactor(ctx, e.request)
}

func (e factorRemoveExecutor) ExecuteCoordinatedProviderOperation(
	ctx context.Context,
	_ auth.AuthorizedOperationContext,
	permit auth.LifecycleExecutionPermit,
) (auth.ProviderOperationOutcome, error) {
	return e.admin.RemoveFactorCoordinated(ctx, e.request, permit)
}

func (e factorRemoveExecutor) ProviderOperationFingerprintFields() []auth.ProviderOperationFingerprintField {
	return []auth.ProviderOperationFingerprintField{
		{Name: "factor_id", Value: e.request.FactorID},
		{Name: "known_state", Value: string(e.request.KnownState)},
		{
			Name:  "remaining_verified_factors",
			Value: strconv.Itoa(e.request.RemainingVerifiedFactors),
		},
		{Name: "allow_last_verified", Value: strconv.FormatBool(e.request.AllowLastVerified)},
	}
}

func (a *AdminClient) RemoveFactorExecutor(
	request auth.FactorRemoveRequest,
) auth.ProviderOperationExecutor {
	return factorRemoveExecutor{admin: a, request: request}
}

var (
	_ auth.CoordinatedProviderOperationExecutor    = accountLifecycleExecutor{}
	_ auth.CoordinatedProviderOperationExecutor    = factorRemoveExecutor{}
	_ auth.ProviderOperationFingerprintContributor = factorRemoveExecutor{}
)
