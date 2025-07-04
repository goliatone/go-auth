package auth

import (
	"context"
	"fmt"
	"time"

	goerrors "github.com/goliatone/go-errors"
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
		return goerrors.Wrap(
			ctx.Err(),
			goerrors.CategoryOperation,
			"context cancelled during password reset initialization",
		)
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

	if event.Stage != ResetInit {
		return goerrors.New("unknown or invalid stage for password reset initialization", goerrors.CategoryBadInput).
			WithMetadata(map[string]any{"stage": event.Stage})
	}

	var err error

	err = h.repo.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// retrieve the user
		user, err = h.repo.Users().GetByIdentifier(ctx, event.Email)
		if err != nil {
			if repository.IsRecordNotFound(err) {
				resp.Stage = AccountVerification
				return nil
			}
			return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to retrieve user for password reset")
		}

		reset.UserID = &user.ID
		reset.Email = event.Email
		reset.Status = ResetRequestedStatus
		if createdReset, err := h.repo.PasswordResets().CreateTx(ctx, tx, reset); err != nil {
			return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to create password reset record")
		} else {
			resp.Reset = createdReset
		}

		go func() {
			// TODO: we need to handle emails...
			printEmailNotification(resp.Reset.Email, resp.Reset.ID.String())
		}()

		resp.Stage = AccountVerification
		return nil
	})

	if err != nil {
		var richErr *goerrors.Error
		if goerrors.As(err, &richErr) {
			return richErr
		}
		return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to initialize password reset")
	}

	resp.Success = true
	event.OnResponse(resp)

	return nil
}

func printEmailNotification(email, id string) {
	fmt.Println("====== SENDING EMAIL NOTIFICATION =======")
	fmt.Printf("to: %s\n", email)
	fmt.Printf(
		"link: /password-reset/%s\n",
		id,
	)
}
