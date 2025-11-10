package auth

import (
	"context"
	"time"

	goerrors "github.com/goliatone/go-errors"
	"github.com/uptrace/bun"
)

type FinalizePasswordResetMesasge struct {
	Session  string `json:"session" example:"350399bc-c095-4bdc-a59c-3352d44848e4" doc:"Reset password session token"`
	Password string `json:"password" example:"some_secret_word" doc:"Password"`
}

type FinalizePasswordResetHandler struct {
	repo     RepositoryManager
	activity ActivitySink
	logger   Logger
}

// NewFinalizePasswordResetHandler creates a handler with sane defaults.
func NewFinalizePasswordResetHandler(repo RepositoryManager) *FinalizePasswordResetHandler {
	return &FinalizePasswordResetHandler{
		repo:     repo,
		activity: noopActivitySink{},
		logger:   defLogger{},
	}
}

// WithActivitySink sets the sink used to emit password reset events.
func (h *FinalizePasswordResetHandler) WithActivitySink(sink ActivitySink) *FinalizePasswordResetHandler {
	h.activity = normalizeActivitySink(sink)
	return h
}

// WithLogger overrides the logger used by the handler.
func (h *FinalizePasswordResetHandler) WithLogger(logger Logger) *FinalizePasswordResetHandler {
	if logger != nil {
		h.logger = logger
	}
	return h
}

func (h *FinalizePasswordResetHandler) Execute(ctx context.Context, event FinalizePasswordResetMesasge) error {
	select {
	case <-ctx.Done():
		return goerrors.Wrap(
			ctx.Err(),
			goerrors.CategoryOperation,
			"context cancelled during password reset finalization",
		)
	default:
		return h.execute(ctx, event)
	}
}

func (h *FinalizePasswordResetHandler) execute(ctx context.Context, event FinalizePasswordResetMesasge) error {
	reset := &PasswordReset{}

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	var err error

	err = h.repo.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// find a password reset by token/id
		reset, err = h.repo.PasswordResets().GetByID(ctx, event.Session)
		if err != nil {
			if goerrors.IsNotFound(err) {
				return goerrors.New("invalid or expired password reset token", goerrors.CategoryNotFound).
					WithCode(goerrors.CodeNotFound)
			}
			return goerrors.Wrap(err, goerrors.CategoryInternal, "could not retrieve password reset request")
		}

		//make sure it was not used
		if reset.Status != ResetRequestedStatus {
			return goerrors.New("password reset token has already been used", goerrors.CategoryConflict).
				WithTextCode("TOKEN_ALREADY_USED")
		}

		if reset.CreatedAt == nil {
			return goerrors.New("password reset record is missing creation date", goerrors.CategoryInternal)
		}

		expired, err := IsOutsideThresholdPeriod(*reset.CreatedAt, "24h")
		if err != nil {
			return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to check token expiration period")
		}

		if expired {
			return goerrors.New("password reset token has expired", goerrors.CategoryValidation).
				WithTextCode(TextCodeTokenExpired)
		}

		passwordHash, err := HashPassword(event.Password)
		if err != nil {
			return goerrors.Wrap(err, goerrors.CategoryValidation, "invalid new password provided")
		}

		if reset.UserID == nil {
			return goerrors.New("password reset record is not associated with a user", goerrors.CategoryInternal)
		}

		_, err = h.repo.Users().RawTx(ctx, tx, ResetUserPasswordSQL, passwordHash, reset.UserID.String())
		if err != nil {
			return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to update user password in database")
		}

		r := MarkPasswordAsReseted(reset.ID)
		if _, err := h.repo.PasswordResets().UpdateTx(ctx, tx, r); err != nil {
			return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to update password reset status")
		}

		return nil
	})

	if err != nil {
		var richErr *goerrors.Error
		if goerrors.As(err, &richErr) {
			return richErr
		}
		return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to finalize password reset")
	}

	h.recordActivity(ctx, reset)

	return nil
}

func (h *FinalizePasswordResetHandler) recordActivity(ctx context.Context, reset *PasswordReset) {
	if reset == nil || reset.UserID == nil {
		return
	}

	event := ActivityEvent{
		EventType: ActivityEventPasswordResetSuccess,
		Actor: ActorRef{
			ID:   reset.UserID.String(),
			Type: "user",
		},
		UserID: reset.UserID.String(),
		Metadata: map[string]any{
			"password_reset_id": reset.ID.String(),
		},
		OccurredAt: time.Now(),
	}

	if err := normalizeActivitySink(h.activity).Record(ctx, event); err != nil {
		h.getLogger().Warn("activity sink error during password reset: %v", err)
	}
}

func (h *FinalizePasswordResetHandler) getLogger() Logger {
	if h.logger != nil {
		return h.logger
	}
	return defLogger{}
}
