package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

type FinalizePasswordResetMesasge struct {
	Session  string `json:"session" example:"350399bc-c095-4bdc-a59c-3352d44848e4" doc:"Reset password session token"`
	Password string `json:"password" example:"some_secret_word" doc:"Password"`
}

type FinalizePasswordResetHandler struct {
	repo RepositoryManager
}

func (h *FinalizePasswordResetHandler) Execute(ctx context.Context, event FinalizePasswordResetMesasge) error {
	reset := &PasswordReset{}

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	var err error

	err = h.repo.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// find a password reset by token/id
		reset, err = h.repo.PasswordResets().GetByID(ctx, event.Session)
		if err != nil {
			return fmt.Errorf("error getting reset: %w", err)
		}

		//make sure it was not used
		if reset.Status != ResetRequestedStatus {
			return fmt.Errorf("password reset used: %w", err)
		}

		if reset.CreatedAt == nil {
			return errors.New("record has no created_at field")
		}

		expired, err := IsOutsideThresholdPeriod(*reset.CreatedAt, "24h")
		if err != nil {
			return fmt.Errorf("error parsing period: %w", err)
		}

		if expired {
			return errors.New("record has expired")
		}

		passwordHash, err := HashPassword(event.Password)
		if err != nil {
			return fmt.Errorf("error hashing password: %w", err)
		}

		if reset.UserID == nil {
			return errors.New("error password reset no user")
		}

		_, err = h.repo.Users().RawTx(ctx, tx, ResetUserPasswordSQL, passwordHash, reset.UserID.String())
		if err != nil {
			return fmt.Errorf("error resetting password: %w", err)
		}

		r := MarkPasswordAsReseted(reset.ID)
		reset, err = h.repo.PasswordResets().UpdateTx(ctx, tx, r)
		if err != nil {
			return fmt.Errorf("error updating reset: %w", err)
		}

		return nil
	})

	return err
}
