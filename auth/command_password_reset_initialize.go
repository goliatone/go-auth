package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/goliatone/go-repository-bun"
	"github.com/uptrace/bun"
)

type InitializePasswordResetMessage struct {
	Stage      string `json:"stage" example:"Rone" doc:"Customer last name."`
	Session    string `json:"session" example:"350399bc-c095-4bdc-a59c-3352d44848e4" doc:"Reset password session token"`
	Email      string `json:"email" example:"pepe.rone@example.com" doc:"Customer email."`
	OnResponse func(resp *InitializePasswordResetResponse)
}

func (p InitializePasswordResetMessage) Type() string { return "user.password_reset" }

type InitializePasswordResetResponse struct {
	Reset   *PasswordReset
	Stage   string
	Success bool
}

type InitializePasswordResetHandler struct {
	repo RepositoryManager
}

func (h *InitializePasswordResetHandler) Execute(ctx context.Context, event InitializePasswordResetMessage) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return h.execute(ctx, event)
	}
}

func (h *InitializePasswordResetHandler) execute(ctx context.Context, event InitializePasswordResetMessage) error {
	user := &User{}
	reset := &PasswordReset{}
	resp := &InitializePasswordResetResponse{}

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	var err error

	switch event.Stage {
	case ResetInit:
		err = h.repo.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
			// retrieve the user
			user, err = h.repo.Users().GetByIdentifier(ctx, event.Email)
			if err != nil {
				if repository.IsRecordNotFound(err) {
					resp.Stage = AccountVerification
					return nil
				}
				return fmt.Errorf("error getting user: %w", err)
			}
			reset.UserID = &user.ID
			reset.Email = event.Email
			reset.Status = ResetRequestedStatus
			reset, err = h.repo.PasswordResets().CreateTx(ctx, tx, reset)
			if err != nil {
				return fmt.Errorf("error creating reset: %w", err)
			}

			go func() {
				// TODO: we need to handle emails...
				printEmailNotification(reset.Email, reset.ID.String())
			}()

			resp.Reset = reset
			resp.Stage = AccountVerification
			return nil
		})
		break
	// User might want to send another email, we need to throttle
	case AccountVerification:
	// We are actually changing the password
	case ChangingPassword:
		break
	default:
		err = errors.New("unkonwn stage")
	}

	resp.Success = true

	event.OnResponse(resp)

	return err
}

func printEmailNotification(email, id string) {
	fmt.Println("====== SENDING EMAIL NOTIFICATION =======")
	fmt.Printf("to: %s\n", email)
	fmt.Printf(
		"link: /password-reset/%s\n",
		id,
	)
}
