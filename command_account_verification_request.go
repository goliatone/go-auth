package auth

import (
	"context"
	"time"

	goerrors "github.com/goliatone/go-errors"
	"github.com/uptrace/bun"
)

type AccountVerificationMesage struct {
	Session    string `json:"session" example:"350399bc-c095-4bdc-a59c-3352d44848e4" doc:"Reset password session token"`
	OnResponse func(a *AccountVerificationResponse)
}

type AccountVerificationResponse struct {
	Stage    string   `json:"stage" example:"Rone" doc:"Customer last name."`
	Redirect string   `json:"redirect" example:"Rone" doc:"Customer last name."`
	Expired  bool     `json:"expired" example:"true" doc:"Has the request expired?"`
	Found    bool     `json:"found" example:"true" doc:"Has the request been found?"`
	Errors   []string `json:"errors" example:"['invalid username']" doc:"Error messages."`
}

type AccountVerificationHandler struct {
	repo RepositoryManager
}

func (h *AccountVerificationHandler) Execute(ctx context.Context, event AccountVerificationMesage) error {
	select {
	case <-ctx.Done():
		return goerrors.Wrap(ctx.Err(), goerrors.CategoryOperation, "context cancelled during account verification")
	default:
		return h.execute(ctx, event)
	}
}

func (h *AccountVerificationHandler) execute(ctx context.Context, event AccountVerificationMesage) error {
	reset := &PasswordReset{}
	resp := &AccountVerificationResponse{}

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	var err error

	err = h.repo.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		reset, err = h.repo.PasswordResets().GetByID(ctx, event.Session)
		if err != nil {
			// if the record is not found, is part of expected flow, not an application error
			if goerrors.IsNotFound(err) {
				resp.Found = false
				return nil
			}
			return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to retrieve verification request")
		}

		resp.Found = true

		if reset.Status != ResetRequestedStatus {
			resp.Expired = true
			return nil
		}

		if reset.CreatedAt == nil {
			return goerrors.New("password reset record is missing creation date", goerrors.CategoryInternal)
		}

		expired, err := IsOutsideThresholdPeriod(*reset.CreatedAt, "24h")
		if err != nil {
			return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to check token expiration period")
		}

		resp.Expired = expired
		return nil
	})

	if err != nil {
		var richErr *goerrors.Error
		if goerrors.As(err, &richErr) {
			return richErr
		}
		return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to execute account verification")
	}

	event.OnResponse(resp)

	return nil
}
