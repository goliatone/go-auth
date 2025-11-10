package auth

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

var ResetUserPasswordSQL = `UPDATE "users" AS "usr"
SET
	"is_email_verified" = TRUE,
	"password_hash" = ?
WHERE
	"usr"."deleted_at" IS NULL
AND (
	"usr"."id" = ?
) RETURNING *;`

type Users interface {
	repository.Repository[*User]

	TrackAttemptedLogin(ctx context.Context, user *User) error
	TrackAttemptedLoginTx(ctx context.Context, tx bun.IDB, user *User) error
	TrackSucccessfulLogin(ctx context.Context, user *User) error
	TrackSucccessfulLoginTx(ctx context.Context, tx bun.IDB, user *User) error

	Register(ctx context.Context, user *User) (*User, error)
	RegisterTx(ctx context.Context, tx bun.IDB, user *User) (*User, error)
	GetOrRegisterTx(ctx context.Context, tx bun.IDB, record *User) (*User, error)
	GetOrCreate(ctx context.Context, record *User) (*User, error)
	GetOrCreateTx(ctx context.Context, tx bun.IDB, record *User) (*User, error)
	Create(ctx context.Context, record *User, criteria ...repository.InsertCriteria) (*User, error)
	CreateTx(ctx context.Context, tx bun.IDB, record *User, criteria ...repository.InsertCriteria) (*User, error)
	Upsert(ctx context.Context, record *User, criteria ...repository.UpdateCriteria) (*User, error)
	UpsertTx(ctx context.Context, tx bun.IDB, record *User, criteria ...repository.UpdateCriteria) (*User, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status UserStatus, opts ...StatusUpdateOption) (*User, error)
	UpdateStatusTx(ctx context.Context, tx bun.IDB, id uuid.UUID, status UserStatus, opts ...StatusUpdateOption) (*User, error)
	Suspend(ctx context.Context, actor ActorRef, user *User, opts ...TransitionOption) (*User, error)
	Reinstate(ctx context.Context, actor ActorRef, user *User, opts ...TransitionOption) (*User, error)

	ResetPassword(ctx context.Context, id uuid.UUID, passwordHash string) error
	ResetPasswordTx(ctx context.Context, tx bun.IDB, id uuid.UUID, passwordHash string) error
}

type users struct {
	repository.Repository[*User]
	db                  *bun.DB
	stateMachine        UserStateMachine
	stateMachineOptions []StateMachineOption
}

var (
	_ Users                        = (*users)(nil)
	_ repository.Repository[*User] = (*users)(nil)
)

type UsersOption func(*users)

func NewUsersRepository(db *bun.DB, opts ...UsersOption) Users {
	repo := repository.NewRepository[*User](db, repository.ModelHandlers[*User]{
		NewRecord: func() *User { return &User{} },
		GetID: func(u *User) uuid.UUID {
			if u == nil {
				return uuid.Nil
			}
			return u.ID
		},
		SetID: func(u *User, id uuid.UUID) {
			if u != nil {
				u.ID = id
			}
		},
	})

	repoUsers := &users{
		Repository: repo,
		db:         db,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(repoUsers)
		}
	}

	return repoUsers
}

func WithUsersStateMachineOptions(options ...StateMachineOption) UsersOption {
	return func(u *users) {
		if len(options) == 0 {
			return
		}
		u.stateMachineOptions = append(u.stateMachineOptions, options...)
		u.stateMachine = nil
	}
}

func WithUsersStateMachine(sm UserStateMachine) UsersOption {
	return func(u *users) {
		u.stateMachine = sm
	}
}

func (a *users) Register(ctx context.Context, user *User) (*User, error) {
	return a.RegisterTx(ctx, a.db, user)
}

func (a *users) RegisterTx(ctx context.Context, tx bun.IDB, user *User) (*User, error) {
	return a.CreateTx(ctx, tx, user)
}

func (a *users) GetByIdentifier(ctx context.Context, identifier string, criteria ...repository.SelectCriteria) (*User, error) {
	return a.GetByIdentifierTx(ctx, a.db, identifier, criteria...)
}

func (a *users) GetByIdentifierTx(ctx context.Context, tx bun.IDB, identifier string, criteria ...repository.SelectCriteria) (*User, error) {
	options := resolveUserIdentifier(identifier)
	if len(options) == 0 {
		options = []identifierOption{
			{
				column: "id",
				value:  strings.TrimSpace(identifier),
			},
		}
	}

	for _, opt := range options {
		record := &User{}
		q := tx.NewSelect().Model(record)

		for _, c := range criteria {
			q.Apply(c)
		}

		err := q.
			Where(fmt.Sprintf("?TableAlias.%s = ?", opt.column), opt.value).
			Limit(1).
			Scan(ctx)

		if err != nil {
			if repository.IsRecordNotFound(err) {
				continue
			}
			return nil, err
		}

		return record, nil
	}

	return nil, repository.NewRecordNotFound().
		WithMetadata(map[string]any{
			"identifier": identifier,
		})
}

func (a *users) Create(ctx context.Context, record *User, criteria ...repository.InsertCriteria) (*User, error) {
	return a.CreateTx(ctx, a.db, record, criteria...)
}

func (a *users) CreateTx(ctx context.Context, tx bun.IDB, record *User, criteria ...repository.InsertCriteria) (*User, error) {
	prepareUserDefaults(record)
	return a.Repository.CreateTx(ctx, tx, record, criteria...)
}

func (a *users) ResetPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	return a.ResetPasswordTx(ctx, a.db, id, passwordHash)
}

func (a *users) ResetPasswordTx(ctx context.Context, tx bun.IDB, id uuid.UUID, passwordHash string) error {
	res, err := a.Repository.RawTx(ctx, tx, ResetUserPasswordSQL, passwordHash, id.String())
	if err != nil {
		return err
	}

	if res == nil || len(res) == 0 {
		return repository.NewRecordNotFound().
			WithMetadata(map[string]any{
				"id": id.String(),
			})
	}

	return nil
}

func (a *users) TrackSucccessfulLogin(ctx context.Context, user *User) error {
	return a.TrackSucccessfulLoginTx(ctx, a.db, user)
}

func (a *users) TrackSucccessfulLoginTx(ctx context.Context, tx bun.IDB, user *User) error {
	// NOTE: Updating using the ORM fails due to a bug, it wont reset
	// login_attempt_at, login_attempts fields.
	loggedInAt := time.Now()
	_, err := tx.NewRaw(`
		UPDATE "users" AS "usr"
		SET
			"loggedin_at" = ?,
			"login_attempt_at" = NULL,
			"login_attempts" = 0
		WHERE
			("usr".id = ?)
			AND "usr"."deleted_at" IS NULL;
	`, loggedInAt, user.ID).Exec(ctx)

	return err
}

func (a *users) TrackAttemptedLogin(ctx context.Context, user *User) error {
	return a.TrackAttemptedLoginTx(ctx, a.db, user)
}

func (a *users) TrackAttemptedLoginTx(ctx context.Context, tx bun.IDB, user *User) error {
	criteria := []repository.UpdateCriteria{
		repository.UpdateByID(user.ID.String()),
	}

	record := &User{}
	record.ID = user.ID
	record.LoginAttempts = user.LoginAttempts + 1
	now := time.Now()
	record.LoginAttemptAt = &now

	_, err := a.Repository.UpdateTx(ctx, tx, record, criteria...)

	return err
}

func (a *users) Upsert(ctx context.Context, record *User, criteria ...repository.UpdateCriteria) (*User, error) {
	return a.UpsertTx(ctx, a.db, record, criteria...)
}

func (a *users) UpsertTx(ctx context.Context, tx bun.IDB, record *User, criteria ...repository.UpdateCriteria) (*User, error) {
	identifier := record.Email
	if record.ID != uuid.Nil {
		identifier = record.ID.String()
	}

	user, err := a.Repository.GetByIdentifierTx(ctx, tx, identifier)
	if err == nil {
		record.ID = user.ID
		return a.Repository.UpdateTx(ctx, tx, record, criteria...)
	}

	if !repository.IsRecordNotFound(err) {
		return nil, err
	}

	return a.RegisterTx(ctx, tx, record)
}

func (a *users) UpdateStatus(ctx context.Context, id uuid.UUID, status UserStatus, opts ...StatusUpdateOption) (*User, error) {
	return a.UpdateStatusTx(ctx, a.db, id, status, opts...)
}

func (a *users) UpdateStatusTx(ctx context.Context, tx bun.IDB, id uuid.UUID, status UserStatus, opts ...StatusUpdateOption) (*User, error) {
	record := &User{
		ID:     id,
		Status: status,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(record)
		}
	}

	return a.Repository.UpdateTx(ctx, tx, record, repository.UpdateByID(id.String()))
}

func (a *users) GetOrRegisterTx(ctx context.Context, tx bun.IDB, record *User) (*User, error) {
	identifier := record.Email
	if record.ID != uuid.Nil {
		identifier = record.ID.String()
	}

	user, err := a.Repository.GetByIdentifierTx(ctx, tx, identifier)
	if err == nil {
		return user, nil
	}

	if !repository.IsRecordNotFound(err) {
		return nil, err
	}

	return a.RegisterTx(ctx, tx, record)
}

func (a *users) GetOrCreate(ctx context.Context, record *User) (*User, error) {
	return a.GetOrCreateTx(ctx, a.db, record)
}

func (a *users) GetOrCreateTx(ctx context.Context, tx bun.IDB, record *User) (*User, error) {
	identifier := record.Email
	if record.ID != uuid.Nil {
		identifier = record.ID.String()
	}

	user, err := a.Repository.GetByIdentifierTx(ctx, tx, identifier)
	if err == nil {
		return user, nil
	}

	if !repository.IsRecordNotFound(err) {
		return nil, err
	}

	return a.CreateTx(ctx, tx, record)
}

func (a *users) Suspend(ctx context.Context, actor ActorRef, user *User, opts ...TransitionOption) (*User, error) {
	return a.lifecycleMachine().Transition(ctx, actor, user, UserStatusSuspended, opts...)
}

func (a *users) Reinstate(ctx context.Context, actor ActorRef, user *User, opts ...TransitionOption) (*User, error) {
	return a.lifecycleMachine().Transition(ctx, actor, user, UserStatusActive, opts...)
}

// StatusUpdateOption allows callers to mutate the user record before persisting status changes.
type StatusUpdateOption func(*User)

// WithSuspendedAt sets the SuspendedAt timestamp during a status transition.
func WithSuspendedAt(at *time.Time) StatusUpdateOption {
	return func(u *User) {
		u.SuspendedAt = at
	}
}

func prepareUserDefaults(record *User) {
	if record == nil {
		return
	}

	if record.Role == "" {
		record.Role = RoleGuest
	}

	record.EnsureStatus()

	if record.ID == uuid.Nil {
		record.ID = uuid.New()
	}
}

type identifierOption struct {
	column string
	value  string
}

func resolveUserIdentifier(identifier string) []identifierOption {
	trimmed := strings.TrimSpace(identifier)
	if trimmed == "" {
		return nil
	}

	options := make([]identifierOption, 0, 3)

	if isUUID(trimmed) {
		options = append(options, identifierOption{
			column: "id",
			value:  trimmed,
		})
	}

	if isEmail(trimmed) {
		options = append(options, identifierOption{
			column: "email",
			value:  trimmed,
		})
	}

	options = append(options, identifierOption{
		column: "username",
		value:  trimmed,
	})

	return options
}

func isEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func isUUID(identifier string) bool {
	_, err := uuid.Parse(identifier)
	return err == nil
}

func (a *users) lifecycleMachine() UserStateMachine {
	if a.stateMachine == nil {
		a.stateMachine = NewUserStateMachine(a, a.stateMachineOptions...)
	}
	return a.stateMachine
}
