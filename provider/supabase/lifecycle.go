package supabase

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/google/uuid"
)

type AdminClient struct {
	client *Client
	clock  func() time.Time
}

func NewAdminClient(client *Client) (*AdminClient, error) {
	if client == nil {
		return nil, ErrInvalidConfig
	}
	return &AdminClient{client: client, clock: func() time.Time { return time.Now().UTC() }}, nil
}

func (a *AdminClient) Invite(ctx context.Context, request auth.InviteRequest) (result auth.ProviderDeliveryOutcome, err error) {
	defer func() {
		a.recordLifecycleActivity(ctx, request.Operation, result.ProviderOperationOutcome, err)
	}()
	if validationErr := a.validateDelivery(request.Operation, auth.ProviderActionInvite, request.Email, request.ReturnURL); validationErr != nil {
		return auth.ProviderDeliveryOutcome{}, validationErr
	}
	var response struct {
		ID string `json:"id"`
	}
	envelope, err := a.client.adminJSON(ctx, requestOptions{
		Method:         http.MethodPost,
		Path:           "/auth/v1/invite",
		Body:           map[string]string{"email": strings.TrimSpace(request.Email), "redirect_to": request.ReturnURL},
		RequestID:      request.Operation.RequestID,
		IdempotencyKey: request.Operation.OperationID,
		RetrySafe:      false,
	}, &response)
	return deliveryOutcome(envelope, request.Operation.RequestID, err)
}

func (a *AdminClient) StartRecovery(ctx context.Context, request auth.RecoveryRequest) (result auth.ProviderDeliveryOutcome, err error) {
	defer func() {
		a.recordLifecycleActivity(ctx, request.Operation, result.ProviderOperationOutcome, err)
	}()
	if validationErr := a.validateDelivery(request.Operation, auth.ProviderActionStartRecovery, request.Email, request.ReturnURL); validationErr != nil {
		return auth.ProviderDeliveryOutcome{}, validationErr
	}
	envelope, err := a.client.publishableJSON(ctx, requestOptions{
		Method:         http.MethodPost,
		Path:           "/auth/v1/recover",
		Body:           map[string]string{"email": strings.TrimSpace(request.Email), "redirect_to": request.ReturnURL},
		RequestID:      request.Operation.RequestID,
		IdempotencyKey: request.Operation.OperationID,
		RetrySafe:      false,
	}, nil)
	return deliveryOutcome(envelope, request.Operation.RequestID, err)
}

func (a *AdminClient) Suspend(ctx context.Context, request auth.AccountLifecycleRequest) (result auth.AccountStateResult, err error) {
	defer func() {
		a.recordLifecycleActivity(ctx, request.Operation, result.ProviderOperationOutcome, err)
	}()
	if err := a.validateAccountOperation(request.Operation, auth.ProviderActionSuspend); err != nil {
		return auth.AccountStateResult{}, err
	}
	return a.updateAccount(ctx, request.Operation, map[string]any{"ban_duration": "876000h"}, auth.ProviderAccountStateSuspended)
}

func (a *AdminClient) Activate(ctx context.Context, request auth.AccountLifecycleRequest) (result auth.AccountStateResult, err error) {
	defer func() {
		a.recordLifecycleActivity(ctx, request.Operation, result.ProviderOperationOutcome, err)
	}()
	if err := a.validateAccountOperation(request.Operation, auth.ProviderActionActivate); err != nil {
		return auth.AccountStateResult{}, err
	}
	return a.updateAccount(ctx, request.Operation, map[string]any{"ban_duration": "none"}, auth.ProviderAccountStateActive)
}

func (a *AdminClient) GetAccountState(ctx context.Context, request auth.AccountLifecycleRequest) (result auth.AccountStateResult, err error) {
	defer func() {
		a.recordLifecycleActivity(ctx, request.Operation, result.ProviderOperationOutcome, err)
	}()
	if validationErr := a.validateAccountOperation(request.Operation, auth.ProviderActionGetAccountState); validationErr != nil {
		return auth.AccountStateResult{}, validationErr
	}
	var response adminUserResponse
	envelope, err := a.client.adminJSON(ctx, requestOptions{
		Method:    http.MethodGet,
		Path:      "/auth/v1/admin/users/" + url.PathEscape(request.Operation.Target.Subject),
		RequestID: request.Operation.RequestID,
		RetrySafe: true,
	}, &response)
	if err != nil {
		return accountErrorOutcome(envelope, request.Operation.RequestID, auth.ProviderAccountStateUnknown, auth.ProviderSessionEffectNone, err)
	}
	state, updatedAt, mapErr := response.normalizedState(a.clock())
	if mapErr != nil {
		return auth.AccountStateResult{}, mapErr
	}
	if response.ID != request.Operation.Target.Subject {
		return auth.AccountStateResult{}, fmt.Errorf("%w: account response target mismatch", ErrProviderUnavailable)
	}
	return auth.AccountStateResult{
		ProviderOperationOutcome: auth.ProviderOperationOutcome{
			Status:            auth.ProviderOperationSucceeded,
			ProviderRequestID: responseRequestID(envelope, request.Operation.RequestID),
		},
		State: state, UpdatedAt: updatedAt,
	}, nil
}

func (a *AdminClient) updateAccount(
	ctx context.Context,
	operation auth.AuthorizedOperationContext,
	body map[string]any,
	expected auth.ProviderAccountState,
) (auth.AccountStateResult, error) {
	var response adminUserResponse
	envelope, err := a.client.adminJSON(ctx, requestOptions{
		Method:         http.MethodPut,
		Path:           "/auth/v1/admin/users/" + url.PathEscape(operation.Target.Subject),
		Body:           body,
		RequestID:      operation.RequestID,
		IdempotencyKey: operation.OperationID,
		RetrySafe:      false,
	}, &response)
	if err != nil {
		return accountErrorOutcome(envelope, operation.RequestID, expected, sessionEffectForAccount(expected), err)
	}
	state, updatedAt, mapErr := response.normalizedState(a.clock())
	if mapErr != nil {
		return auth.AccountStateResult{}, mapErr
	}
	if response.ID != operation.Target.Subject {
		return auth.AccountStateResult{}, fmt.Errorf("%w: account response target mismatch", ErrProviderUnavailable)
	}
	if state != expected {
		return auth.AccountStateResult{
			ProviderOperationOutcome: auth.ProviderOperationOutcome{
				Status:                auth.ProviderOperationPending,
				ProviderRequestID:     responseRequestID(envelope, operation.RequestID),
				ProviderSessionEffect: sessionEffectForAccount(expected),
			},
			State: state, UpdatedAt: updatedAt,
		}, auth.ErrProviderOperationPending
	}
	return auth.AccountStateResult{
		ProviderOperationOutcome: auth.ProviderOperationOutcome{
			Status:                auth.ProviderOperationSucceeded,
			ProviderRequestID:     responseRequestID(envelope, operation.RequestID),
			ProviderSessionEffect: sessionEffectForAccount(expected),
		},
		State: state, UpdatedAt: updatedAt,
	}, nil
}

func (a *AdminClient) validateDelivery(
	operation auth.AuthorizedOperationContext,
	action auth.ProviderOperationAction,
	email, returnURL string,
) error {
	if a == nil || a.client == nil {
		return ErrProviderUnavailable
	}
	if err := operation.Validate(action, a.client.config.Environment, ProviderKey); err != nil {
		return err
	}
	normalizedEmail, err := validEmail(email)
	if err != nil || !strings.EqualFold(strings.TrimSpace(operation.Target.Subject), normalizedEmail) {
		return fmt.Errorf("%w: delivery target mismatch", auth.ErrProviderOperationInvalid)
	}
	if !a.client.config.ReturnURLAllowed(returnURL) {
		return fmt.Errorf("%w: delivery return URL is not allowed", auth.ErrProviderOperationInvalid)
	}
	return nil
}

func (a *AdminClient) validateAccountOperation(operation auth.AuthorizedOperationContext, action auth.ProviderOperationAction) error {
	if a == nil || a.client == nil {
		return ErrProviderUnavailable
	}
	if err := operation.Validate(action, a.client.config.Environment, ProviderKey); err != nil {
		return err
	}
	if _, err := uuid.Parse(strings.TrimSpace(operation.Target.Subject)); err != nil {
		return fmt.Errorf("%w: account target must be a UUID", auth.ErrProviderOperationInvalid)
	}
	return nil
}

func validEmail(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 254 {
		return "", fmt.Errorf("invalid email")
	}
	parsed, err := mail.ParseAddress(raw)
	if err != nil || parsed.Address != raw {
		return "", fmt.Errorf("invalid email")
	}
	return strings.ToLower(parsed.Address), nil
}

type adminUserResponse struct {
	ID          string     `json:"id"`
	BannedUntil *time.Time `json:"banned_until"`
	DeletedAt   *time.Time `json:"deleted_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (r adminUserResponse) normalizedState(now time.Time) (auth.ProviderAccountState, time.Time, error) {
	if _, err := uuid.Parse(strings.TrimSpace(r.ID)); err != nil {
		return auth.ProviderAccountStateUnknown, time.Time{}, fmt.Errorf("%w: malformed account response", ErrProviderUnavailable)
	}
	if r.UpdatedAt.IsZero() {
		return auth.ProviderAccountStateUnknown, time.Time{}, fmt.Errorf("%w: account response is missing update time", ErrProviderUnavailable)
	}
	switch {
	case r.DeletedAt != nil && !r.DeletedAt.IsZero():
		return auth.ProviderAccountStateDisabled, r.UpdatedAt, nil
	case r.BannedUntil != nil && r.BannedUntil.After(now):
		return auth.ProviderAccountStateSuspended, r.UpdatedAt, nil
	default:
		return auth.ProviderAccountStateActive, r.UpdatedAt, nil
	}
}

func deliveryOutcome(envelope responseEnvelope, fallbackRequestID string, err error) (auth.ProviderDeliveryOutcome, error) {
	requestID := responseRequestID(envelope, fallbackRequestID)
	if err == nil {
		return auth.ProviderDeliveryOutcome{
			ProviderOperationOutcome: auth.ProviderOperationOutcome{
				Status: auth.ProviderOperationSucceeded, ProviderRequestID: requestID,
			},
			Delivery: auth.ProviderDeliverySent,
		}, nil
	}
	if errors.Is(err, auth.ErrProviderOperationConflict) {
		var providerErr *ProviderError
		if !errors.As(err, &providerErr) ||
			(providerErr.Code != "user_already_exists" &&
				providerErr.Code != "email_exists" &&
				providerErr.Code != "already_invited" &&
				providerErr.Code != "already_recovery_pending") {
			return auth.ProviderDeliveryOutcome{
				ProviderOperationOutcome: auth.ProviderOperationOutcome{
					Status: auth.ProviderOperationConflict, ProviderRequestID: requestID,
				},
				Delivery: auth.ProviderDeliveryFailed,
			}, err
		}
		return auth.ProviderDeliveryOutcome{
			ProviderOperationOutcome: auth.ProviderOperationOutcome{
				Status: auth.ProviderOperationAlreadyComplete, ProviderRequestID: requestID,
			},
			Delivery: auth.ProviderDeliveryDuplicate,
		}, nil
	}
	if errors.Is(err, ErrAmbiguousMutation) {
		return auth.ProviderDeliveryOutcome{
			ProviderOperationOutcome: auth.ProviderOperationOutcome{
				Status: auth.ProviderOperationPending, ProviderRequestID: requestID,
			},
			Delivery: auth.ProviderDeliveryPending,
		}, auth.ErrProviderOperationPending
	}
	return auth.ProviderDeliveryOutcome{
		ProviderOperationOutcome: auth.ProviderOperationOutcome{
			Status: auth.ProviderOperationFailed, ProviderRequestID: requestID,
		},
		Delivery: auth.ProviderDeliveryFailed,
	}, err
}

func accountErrorOutcome(
	envelope responseEnvelope,
	fallbackRequestID string,
	expected auth.ProviderAccountState,
	effect auth.ProviderSessionEffect,
	err error,
) (auth.AccountStateResult, error) {
	status := auth.ProviderOperationFailed
	state := auth.ProviderAccountStateUnknown
	switch {
	case errors.Is(err, auth.ErrProviderOperationConflict):
		var providerErr *ProviderError
		if errors.As(err, &providerErr) &&
			(providerErr.Code == "already_suspended" || providerErr.Code == "already_active" || providerErr.Code == "already_complete") {
			status, state, err = auth.ProviderOperationAlreadyComplete, expected, nil
		} else {
			status = auth.ProviderOperationConflict
		}
	case errors.Is(err, ErrAmbiguousMutation):
		status = auth.ProviderOperationPending
		err = auth.ErrProviderOperationPending
	case errors.Is(err, auth.ErrProviderOperationUnsupported):
		status = auth.ProviderOperationUnsupported
	}
	return auth.AccountStateResult{
		ProviderOperationOutcome: auth.ProviderOperationOutcome{
			Status:                status,
			ProviderRequestID:     responseRequestID(envelope, fallbackRequestID),
			ProviderSessionEffect: effect,
		},
		State: state,
	}, err
}

func responseRequestID(envelope responseEnvelope, fallback string) string {
	return firstNonEmpty(envelope.Header.Get("X-Request-ID"), fallback)
}

func sessionEffectForAccount(state auth.ProviderAccountState) auth.ProviderSessionEffect {
	if state == auth.ProviderAccountStateSuspended {
		return auth.ProviderSessionEffectAllForUser
	}
	return auth.ProviderSessionEffectNone
}

var (
	_ auth.IdentityLifecycle = (*AdminClient)(nil)
	_ auth.AccountLifecycle  = (*AdminClient)(nil)
)
