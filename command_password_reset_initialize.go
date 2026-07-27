package auth

import (
	"context"
	"time"

	goerrors "github.com/goliatone/go-errors"
	"github.com/goliatone/go-featuregate/gate"
	"github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
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
	// Reset is retained for source compatibility. Password reset credentials
	// are never returned through command responses.
	Reset   *PasswordReset
	Stage   string
	Success bool
}

// PasswordResetDeliveryRequest contains the minimum capability required by a
// trusted out-of-band delivery implementation. Token is deliberately opaque so
// common formatting and serialization paths redact it.
type PasswordResetDeliveryRequest struct {
	Email     string
	Token     Secret
	ExpiresAt time.Time
}

// PasswordResetDelivery delivers a password reset credential over a trusted
// out-of-band channel, such as email.
type PasswordResetDelivery interface {
	DeliverPasswordReset(context.Context, PasswordResetDeliveryRequest) error
}

// PasswordResetDeliveryFunc adapts a function to PasswordResetDelivery.
type PasswordResetDeliveryFunc func(context.Context, PasswordResetDeliveryRequest) error

func (f PasswordResetDeliveryFunc) DeliverPasswordReset(ctx context.Context, req PasswordResetDeliveryRequest) error {
	return f(ctx, req)
}

type InitializePasswordResetHandler struct {
	repo        RepositoryManager
	featureGate gate.FeatureGate
	delivery    PasswordResetDelivery
	logger      Logger
	provider    LoggerProvider
}

func NewInitializePasswordResetHandler(repo RepositoryManager) *InitializePasswordResetHandler {
	loggerProvider, logger := ResolveLogger("auth.password_reset", nil, nil)
	return &InitializePasswordResetHandler{
		repo:     repo,
		logger:   logger,
		provider: loggerProvider,
	}
}

func (h *InitializePasswordResetHandler) WithFeatureGate(featureGate gate.FeatureGate) *InitializePasswordResetHandler {
	h.featureGate = featureGate
	return h
}

// WithDelivery configures the trusted out-of-band reset credential delivery.
func (h *InitializePasswordResetHandler) WithDelivery(delivery PasswordResetDelivery) *InitializePasswordResetHandler {
	h.delivery = delivery
	return h
}

// WithLogger overrides the logger used by the handler.
func (h *InitializePasswordResetHandler) WithLogger(logger Logger) *InitializePasswordResetHandler {
	h.provider, h.logger = ResolveLogger("auth.password_reset", h.provider, logger)
	return h
}

// WithLoggerProvider overrides the logger provider used by the handler.
func (h *InitializePasswordResetHandler) WithLoggerProvider(provider LoggerProvider) *InitializePasswordResetHandler {
	h.provider, h.logger = ResolveLogger("auth.password_reset", provider, h.logger)
	return h
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
		if err := requireFeatureGate(ctx, h.featureGate, gate.FeatureUsersPasswordReset, ErrPasswordResetDisabled); err != nil {
			return err
		}
		return h.execute(ctx, event)
	}
}

func (h *InitializePasswordResetHandler) execute(ctx context.Context, event InitializePasswordResetMessage) error {
	resp := &InitializePasswordResetResponse{
		Stage: AccountVerification,
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	if event.Stage != ResetInit {
		return goerrors.New("unknown or invalid stage for password reset initialization", goerrors.CategoryBadInput).
			WithMetadata(map[string]any{"stage": event.Stage})
	}

	var createdReset *PasswordReset
	err := h.repo.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		user, err := h.repo.Users().GetByIdentifier(ctx, event.Email)
		if err != nil {
			if repository.IsRecordNotFound(err) {
				return nil
			}
			return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to retrieve user for password reset")
		}

		// Fail closed when no trusted delivery capability is configured. The
		// public response remains identical to the unknown-account path.
		if h.delivery == nil {
			return nil
		}

		reset := &PasswordReset{}
		reset.UserID = &user.ID
		reset.Email = event.Email
		reset.Status = ResetRequestedStatus
		createdReset, err = h.repo.PasswordResets().CreateTx(ctx, tx, reset)
		if err != nil {
			return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to create password reset record")
		}
		return nil
	})

	if err != nil {
		var richErr *goerrors.Error
		if goerrors.As(err, &richErr) {
			return richErr
		}
		return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to initialize password reset")
	}

	if createdReset != nil {
		deliveryErr := h.delivery.DeliverPasswordReset(ctx, PasswordResetDeliveryRequest{
			Email:     createdReset.Email,
			Token:     NewSecret(createdReset.ID.String()),
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		})
		if deliveryErr != nil {
			h.invalidateUndeliveredReset(ctx, createdReset.ID)
			EnsureLogger(h.logger).Error("password reset delivery failed", "error", deliveryErr)
		}
	}

	resp.Success = true
	if event.OnResponse != nil {
		event.OnResponse(resp)
	}

	return nil
}

func (h *InitializePasswordResetHandler) invalidateUndeliveredReset(ctx context.Context, resetID uuid.UUID) {
	record := &PasswordReset{ID: resetID, Status: ResetExpiredStatus}
	now := time.Now().UTC()
	record.UpdatedAt = &now
	if _, err := h.repo.PasswordResets().Update(
		ctx,
		record,
		repository.UpdateColumns("status", "updated_at"),
	); err != nil {
		EnsureLogger(h.logger).Error("failed to invalidate undelivered password reset", "error", err)
	}
}
