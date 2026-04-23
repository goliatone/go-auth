package auth

import (
	"context"
	"time"

	goerrors "github.com/goliatone/go-errors"
	"github.com/goliatone/go-featuregate/gate"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type FinalizePasswordResetMesasge struct {
	Session  string `json:"session" example:"350399bc-c095-4bdc-a59c-3352d44848e4" doc:"Reset password session token"`
	Password string `json:"password" example:"some_secret_word" doc:"Password"`
}

type FinalizePasswordResetHandler struct {
	repo        RepositoryManager
	activity    ActivitySink
	logger      Logger
	provider    LoggerProvider
	featureGate gate.FeatureGate
}

// NewFinalizePasswordResetHandler creates a handler with sane defaults.
func NewFinalizePasswordResetHandler(repo RepositoryManager) *FinalizePasswordResetHandler {
	loggerProvider, logger := ResolveLogger("auth.password_reset", nil, nil)
	return &FinalizePasswordResetHandler{
		repo:     repo,
		activity: noopActivitySink{},
		logger:   logger,
		provider: loggerProvider,
	}
}

// WithActivitySink sets the sink used to emit password reset events.
func (h *FinalizePasswordResetHandler) WithActivitySink(sink ActivitySink) *FinalizePasswordResetHandler {
	h.activity = normalizeActivitySink(sink)
	return h
}

// WithLogger overrides the logger used by the handler.
func (h *FinalizePasswordResetHandler) WithLogger(logger Logger) *FinalizePasswordResetHandler {
	h.provider, h.logger = ResolveLogger("auth.password_reset", h.provider, logger)
	return h
}

// WithLoggerProvider overrides the logger provider used by the handler.
func (h *FinalizePasswordResetHandler) WithLoggerProvider(provider LoggerProvider) *FinalizePasswordResetHandler {
	h.provider, h.logger = ResolveLogger("auth.password_reset", provider, h.logger)
	return h
}

// WithFeatureGate sets the feature gate used to authorize reset completion.
func (h *FinalizePasswordResetHandler) WithFeatureGate(featureGate gate.FeatureGate) *FinalizePasswordResetHandler {
	h.featureGate = featureGate
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
		if err := requirePasswordResetGate(ctx, h.featureGate, true); err != nil {
			return err
		}
		return h.execute(ctx, event)
	}
}

func (h *FinalizePasswordResetHandler) execute(ctx context.Context, event FinalizePasswordResetMesasge) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	var reset *PasswordReset
	err := h.repo.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		var txErr error
		reset, txErr = h.finalizePasswordResetTx(ctx, tx, event)
		return txErr
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

func (h *FinalizePasswordResetHandler) finalizePasswordResetTx(ctx context.Context, tx bun.Tx, event FinalizePasswordResetMesasge) (*PasswordReset, error) {
	reset, err := h.loadPendingPasswordReset(ctx, event.Session)
	if err != nil {
		return nil, err
	}

	if err := h.validatePasswordReset(reset); err != nil {
		return nil, err
	}

	passwordHash, err := h.hashPassword(event.Password)
	if err != nil {
		return nil, err
	}

	if err := h.updateResetUserPassword(ctx, tx, reset, passwordHash); err != nil {
		return nil, err
	}

	if err := h.markPasswordResetComplete(ctx, tx, reset.ID); err != nil {
		return nil, err
	}

	return reset, nil
}

func (h *FinalizePasswordResetHandler) loadPendingPasswordReset(ctx context.Context, session string) (*PasswordReset, error) {
	reset, err := h.repo.PasswordResets().GetByID(ctx, session)
	if err != nil {
		if goerrors.IsNotFound(err) {
			return nil, goerrors.New("invalid or expired password reset token", goerrors.CategoryNotFound).
				WithCode(goerrors.CodeNotFound)
		}
		return nil, goerrors.Wrap(err, goerrors.CategoryInternal, "could not retrieve password reset request")
	}

	return reset, nil
}

func (h *FinalizePasswordResetHandler) validatePasswordReset(reset *PasswordReset) error {
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

	return nil
}

func (h *FinalizePasswordResetHandler) hashPassword(password string) (string, error) {
	passwordHash, err := HashPassword(password)
	if err != nil {
		return "", goerrors.Wrap(err, goerrors.CategoryValidation, "invalid new password provided")
	}
	return passwordHash, nil
}

func (h *FinalizePasswordResetHandler) updateResetUserPassword(ctx context.Context, tx bun.Tx, reset *PasswordReset, passwordHash string) error {
	if reset.UserID == nil {
		return goerrors.New("password reset record is not associated with a user", goerrors.CategoryInternal)
	}

	usersRepo := h.repo.Users()
	user, err := usersRepo.GetByIDTx(ctx, tx, reset.UserID.String())
	if err != nil {
		return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to load reset user")
	}

	if HasTemporaryPasswordMetadata(user.Metadata) {
		resetRepo, ok := usersRepo.(TemporaryPasswordResetRepository)
		if !ok {
			return goerrors.New("users repository does not support temporary password reset cleanup", goerrors.CategoryInternal)
		}
		return h.resetTemporaryPasswordTx(ctx, tx, resetRepo, *reset.UserID, passwordHash)
	}

	if err := usersRepo.ResetPasswordTx(ctx, tx, *reset.UserID, passwordHash); err != nil {
		return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to update user password in database")
	}

	return nil
}

func (h *FinalizePasswordResetHandler) resetTemporaryPasswordTx(ctx context.Context, tx bun.Tx, repo TemporaryPasswordResetRepository, userID uuid.UUID, passwordHash string) error {
	if err := repo.ResetPasswordAndClearTemporaryPasswordTx(ctx, tx, userID, passwordHash); err != nil {
		return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to update user password in database")
	}
	return nil
}

func (h *FinalizePasswordResetHandler) markPasswordResetComplete(ctx context.Context, tx bun.Tx, resetID uuid.UUID) error {
	record := MarkPasswordAsReseted(resetID)
	if _, err := h.repo.PasswordResets().UpdateTx(ctx, tx, record); err != nil {
		return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to update password reset status")
	}
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
		h.getLogger().Warn("activity sink error during password reset", "error", err)
	}
}

func (h *FinalizePasswordResetHandler) getLogger() Logger {
	return EnsureLogger(h.logger)
}
