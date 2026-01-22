package auth

import (
	"context"

	"github.com/goliatone/go-errors"
	"github.com/goliatone/go-featuregate/gate"
	"github.com/goliatone/go-featuregate/gate/guard"
)

func normalizeFeatureGateError(err error) error {
	if err == nil {
		return nil
	}

	var richErr *errors.Error
	if errors.As(err, &richErr) {
		return err
	}

	return errors.Wrap(err, errors.CategoryAuthz, "Feature gate check failed").
		WithCode(errors.CodeForbidden)
}

func requireFeatureGate(ctx context.Context, featureGate gate.FeatureGate, key string, disabledErr error) error {
	return guard.Require(ctx, featureGate, key,
		guard.WithDisabledError(disabledErr),
		guard.WithErrorMapper(normalizeFeatureGateError),
	)
}

func requirePasswordResetGate(ctx context.Context, featureGate gate.FeatureGate, allowFinalize bool) error {
	opts := []guard.Option{
		guard.WithDisabledError(ErrPasswordResetDisabled),
		guard.WithErrorMapper(normalizeFeatureGateError),
	}
	if allowFinalize {
		opts = append(opts, guard.WithOverrides(gate.FeatureUsersPasswordResetFinalize))
	}
	return guard.Require(ctx, featureGate, gate.FeatureUsersPasswordReset, opts...)
}
