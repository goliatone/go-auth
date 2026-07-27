package supabase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/google/uuid"
)

func (a *AdminClient) ListFactors(ctx context.Context, request auth.FactorListRequest) (result auth.ProviderFactorsResult, err error) {
	defer func() {
		a.recordLifecycleActivity(ctx, request.Operation, result.ProviderOperationOutcome, err)
	}()
	if validationErr := a.validateFactorOperation(request.Operation, auth.ProviderActionListFactors); validationErr != nil {
		return auth.ProviderFactorsResult{}, validationErr
	}
	var response json.RawMessage
	envelope, err := a.client.adminJSON(ctx, requestOptions{
		Method:    http.MethodGet,
		Path:      "/auth/v1/admin/users/" + url.PathEscape(request.Operation.Target.Subject) + "/factors",
		RequestID: request.Operation.RequestID,
		RetrySafe: true,
	}, &response)
	if err != nil {
		return factorListError(envelope, request.Operation.RequestID, err)
	}
	factors, err := decodeFactors(response)
	if err != nil {
		return auth.ProviderFactorsResult{}, err
	}
	return auth.ProviderFactorsResult{
		ProviderOperationOutcome: auth.ProviderOperationOutcome{
			Status: auth.ProviderOperationSucceeded, ProviderRequestID: responseRequestID(envelope, request.Operation.RequestID),
		},
		Factors: factors,
	}, nil
}

//nolint:gocyclo // Factor target, state, and last-factor safety checks remain explicit.
func (a *AdminClient) RemoveFactor(ctx context.Context, request auth.FactorRemoveRequest) (result auth.ProviderOperationOutcome, err error) {
	defer func() {
		a.recordLifecycleActivity(ctx, request.Operation, result, err)
	}()
	if validationErr := a.validateFactorOperation(request.Operation, auth.ProviderActionRemoveFactor); validationErr != nil {
		return auth.ProviderOperationOutcome{}, validationErr
	}
	factorUUID, err := uuid.Parse(strings.TrimSpace(request.FactorID))
	if err != nil {
		return auth.ProviderOperationOutcome{}, fmt.Errorf("%w: factor ID must be a UUID", auth.ErrProviderOperationInvalid)
	}
	targetUUID, err := uuid.Parse(strings.TrimSpace(request.Operation.Target.ObjectID))
	if err != nil || targetUUID != factorUUID {
		return auth.ProviderOperationOutcome{}, fmt.Errorf("%w: authorized factor target mismatch", auth.ErrProviderOperationUnauthorized)
	}
	factor, verifiedCount, err := a.authoritativeFactor(ctx, request.Operation, factorUUID.String())
	if err != nil {
		return auth.ProviderOperationOutcome{Status: auth.ProviderOperationFailed}, err
	}
	if request.KnownState != "" && request.KnownState != factor.State {
		return auth.ProviderOperationOutcome{Status: auth.ProviderOperationConflict}, auth.ErrProviderOperationConflict
	}
	if request.RemainingVerifiedFactors < 0 ||
		(request.RemainingVerifiedFactors > 0 && request.RemainingVerifiedFactors != verifiedCount) {
		return auth.ProviderOperationOutcome{Status: auth.ProviderOperationConflict}, auth.ErrProviderOperationConflict
	}
	if factor.State == auth.ProviderFactorVerified &&
		!request.AllowLastVerified && verifiedCount <= 1 {
		return auth.ProviderOperationOutcome{
			Status: auth.ProviderOperationConflict,
		}, auth.ErrProviderOperationConflict
	}
	effect := auth.ProviderSessionEffectNone
	if factor.State == auth.ProviderFactorVerified {
		effect = auth.ProviderSessionEffectAllForUser
	}
	envelope, err := a.client.adminJSON(ctx, requestOptions{
		Method: http.MethodDelete,
		Path: "/auth/v1/admin/users/" + url.PathEscape(request.Operation.Target.Subject) +
			"/factors/" + url.PathEscape(factor.ID),
		RequestID:      request.Operation.RequestID,
		IdempotencyKey: request.Operation.OperationID,
		RetrySafe:      false,
	}, nil)
	if err == nil {
		return auth.ProviderOperationOutcome{
			Status: auth.ProviderOperationSucceeded, ProviderRequestID: responseRequestID(envelope, request.Operation.RequestID),
			ProviderSessionEffect: effect,
		}, nil
	}
	status := auth.ProviderOperationFailed
	switch {
	case errors.Is(err, auth.ErrProviderOperationUnsupported):
		status = auth.ProviderOperationUnsupported
	case errors.Is(err, auth.ErrProviderOperationConflict):
		status = auth.ProviderOperationConflict
	case errors.Is(err, ErrAmbiguousMutation):
		status, err = auth.ProviderOperationPending, auth.ErrProviderOperationPending
	}
	return auth.ProviderOperationOutcome{
		Status: status, ProviderRequestID: responseRequestID(envelope, request.Operation.RequestID),
		ProviderSessionEffect: effect,
	}, err
}

func (a *AdminClient) authoritativeFactor(
	ctx context.Context,
	operation auth.AuthorizedOperationContext,
	factorID string,
) (auth.ProviderFactor, int, error) {
	var response json.RawMessage
	_, err := a.client.adminJSON(ctx, requestOptions{
		Method:    http.MethodGet,
		Path:      "/auth/v1/admin/users/" + url.PathEscape(operation.Target.Subject) + "/factors",
		RequestID: operation.RequestID,
		RetrySafe: true,
	}, &response)
	if err != nil {
		return auth.ProviderFactor{}, 0, err
	}
	factors, err := decodeFactors(response)
	if err != nil {
		return auth.ProviderFactor{}, 0, err
	}
	var selected auth.ProviderFactor
	verifiedCount := 0
	for _, factor := range factors {
		if factor.State == auth.ProviderFactorVerified {
			verifiedCount++
		}
		if factor.ID == factorID {
			selected = factor
		}
	}
	if selected.ID == "" {
		return auth.ProviderFactor{}, verifiedCount, auth.ErrProviderOperationConflict
	}
	return selected, verifiedCount, nil
}

func (a *AdminClient) validateFactorOperation(operation auth.AuthorizedOperationContext, action auth.ProviderOperationAction) error {
	if a == nil || a.client == nil {
		return ErrProviderUnavailable
	}
	if err := operation.Validate(action, a.client.config.Environment, ProviderKey); err != nil {
		return err
	}
	if _, err := uuid.Parse(strings.TrimSpace(operation.Target.Subject)); err != nil {
		return fmt.Errorf("%w: factor owner must be a UUID", auth.ErrProviderOperationInvalid)
	}
	return nil
}

type factorResponse struct {
	ID           string    `json:"id"`
	FactorType   string    `json:"factor_type"`
	Status       string    `json:"status"`
	FriendlyName string    `json:"friendly_name"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func decodeFactors(raw json.RawMessage) ([]auth.ProviderFactor, error) {
	var wrapped struct {
		Factors []factorResponse `json:"factors"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		var direct []factorResponse
		if directErr := json.Unmarshal(raw, &direct); directErr != nil {
			return nil, fmt.Errorf("%w: malformed factor response", ErrProviderUnavailable)
		}
		wrapped.Factors = direct
	}
	seen := map[string]struct{}{}
	out := make([]auth.ProviderFactor, 0, len(wrapped.Factors))
	for _, factor := range wrapped.Factors {
		if _, err := uuid.Parse(strings.TrimSpace(factor.ID)); err != nil ||
			factor.CreatedAt.IsZero() || factor.UpdatedAt.IsZero() {
			return nil, fmt.Errorf("%w: malformed factor response", ErrProviderUnavailable)
		}
		if _, exists := seen[factor.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate factor response", ErrProviderUnavailable)
		}
		seen[factor.ID] = struct{}{}
		state := auth.ProviderFactorState(strings.ToLower(strings.TrimSpace(factor.Status)))
		if state != auth.ProviderFactorVerified && state != auth.ProviderFactorUnverified {
			return nil, fmt.Errorf("%w: unknown factor verification state", ErrProviderUnavailable)
		}
		factorType := auth.ProviderFactorType(strings.ToLower(strings.TrimSpace(factor.FactorType)))
		if !slices.Contains([]auth.ProviderFactorType{
			auth.ProviderFactorTOTP, auth.ProviderFactorPhone, auth.ProviderFactorWebAuthn,
		}, factorType) {
			factorType = auth.ProviderFactorUnknown
		}
		out = append(out, auth.ProviderFactor{
			ID: factor.ID, Type: factorType, State: state,
			FriendlyName: strings.TrimSpace(factor.FriendlyName),
			CreatedAt:    factor.CreatedAt, UpdatedAt: factor.UpdatedAt,
		})
	}
	return out, nil
}

func factorListError(envelope responseEnvelope, fallback string, err error) (auth.ProviderFactorsResult, error) {
	status := auth.ProviderOperationFailed
	if errors.Is(err, auth.ErrProviderOperationUnsupported) {
		status = auth.ProviderOperationUnsupported
	}
	return auth.ProviderFactorsResult{
		ProviderOperationOutcome: auth.ProviderOperationOutcome{
			Status: status, ProviderRequestID: responseRequestID(envelope, fallback),
		},
	}, err
}

var _ auth.FactorLifecycle = (*AdminClient)(nil)
