package auth

import (
	"context"
	"strings"
	"time"

	goerrors "github.com/goliatone/go-errors"
	"github.com/goliatone/hashid/pkg/hashid"
	"github.com/uptrace/bun"
)

type RegisterUserMessage struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	Role      string `json:"role"`
	Password  string `json:"password"`
	UseHashid bool
}

func (e RegisterUserMessage) Type() string { return "user.register" }

// Test handlers
type RegisterUserHandler struct {
	repo RepositoryManager
}

func (h *RegisterUserHandler) Execute(ctx context.Context, event RegisterUserMessage) error {
	select {
	case <-ctx.Done():
		return goerrors.Wrap(
			ctx.Err(),
			goerrors.CategoryOperation,
			"context cancelled during user registration",
		)
	default:
		return h.execute(ctx, event)
	}
}

func (h *RegisterUserHandler) execute(ctx context.Context, event RegisterUserMessage) error {
	user := &User{}
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	err := h.repo.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		hash, err := HashPassword(event.Password)
		if err != nil {
			var richErr *goerrors.Error
			if goerrors.As(err, &richErr) {
				return goerrors.Wrap(richErr, goerrors.CategoryValidation, "invalid password provided")
			}
			return goerrors.Wrap(err, goerrors.CategoryInternal, "failed to hash password")
		}

		user.PasswordHash = hash
		user.Email = event.Email
		user.Phone = event.Phone
		user.FirstName = event.FirstName
		user.LastName = event.LastName
		user.Username = getUsername(event.Username, event.Email)
		if event.UseHashid {
			if id, err := hashid.NewUUID(event.Email); err == nil {
				user.ID = id
			}
		}

		if user, err = h.repo.Users().CreateTx(ctx, tx, user); err != nil {
			return goerrors.Wrap(err, goerrors.CategoryConflict, "could not create user")
		}

		return nil
	})

	if err != nil {
		var richErr *goerrors.Error
		if goerrors.As(err, &richErr) {
			return richErr
		}

		return goerrors.Wrap(err, goerrors.CategoryInternal, "user registration transaction failed")
	}

	return nil
}

func getUsername(username, email string) string {
	if username != "" {
		return username
	}

	if strings.Contains(email, "@") {
		username = strings.Split(email, "@")[0]
	}

	return username
}
