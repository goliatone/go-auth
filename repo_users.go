package auth

import (
	"context"
	"fmt"
	"net/mail"
	"time"

	"github.com/goliatone/go-errors"
	"github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
	"github.com/nyaruka/phonenumbers"
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
	Raw(ctx context.Context, sql string, args ...any) ([]*User, error)
	RawTx(ctx context.Context, tx bun.IDB, sql string, args ...any) ([]*User, error)

	Get(ctx context.Context, criteria ...repository.SelectCriteria) (*User, error)
	GetByID(ctx context.Context, id string, criteria ...repository.SelectCriteria) (*User, error)
	GetByIdentifier(ctx context.Context, identifier string) (*User, error)
	GetByIdentifierTx(ctx context.Context, tx bun.IDB, identifier string) (*User, error)

	TrackAttemptedLogin(ctx context.Context, user *User) error
	TrackAttemptedLoginTx(ctx context.Context, tx bun.IDB, user *User) error
	TrackSucccessfulLogin(ctx context.Context, user *User) error
	TrackSucccessfulLoginTx(ctx context.Context, tx bun.IDB, user *User) error

	Register(ctx context.Context, user *User) (*User, error)
	RegisterTx(ctx context.Context, tx bun.IDB, user *User) (*User, error)
	GetOrRegisterTx(ctx context.Context, tx bun.IDB, record *User) (*User, error)
	CreateTx(ctx context.Context, tx bun.IDB, record *User) (*User, error)

	GetOrCreate(ctx context.Context, record *User) (*User, error)
	GetOrCreateTx(ctx context.Context, tx bun.IDB, record *User) (*User, error)

	Update(ctx context.Context, record *User, criteria ...repository.UpdateCriteria) (*User, error)
	UpdateTx(ctx context.Context, tx bun.IDB, record *User, criteria ...repository.UpdateCriteria) (*User, error)

	Upsert(ctx context.Context, record *User, criteria ...repository.UpdateCriteria) (*User, error)
	UpsertTx(ctx context.Context, tx bun.IDB, record *User, criteria ...repository.UpdateCriteria) (*User, error)

	ResetPassword(ctx context.Context, id uuid.UUID, passwordHash string) error
	ResetPasswordTx(ctx context.Context, tx bun.IDB, id uuid.UUID, passwordHash string) error
}

type users struct {
	db     *bun.DB
	driver string
}

func NewUsersRepository(db *bun.DB) Users {
	return &users{
		db:     db,
		driver: repository.DetectDriver(db),
	}
}

func (a *users) mapError(err error) error {
	if err == nil {
		return nil
	}

	if errors.IsWrapped(err) {
		return err
	}

	return repository.MapDatabaseError(err, a.driver)
}

func (a *users) Raw(ctx context.Context, sql string, args ...any) ([]*User, error) {
	return a.RawTx(ctx, a.db, sql, args...)
}

func (a *users) RawTx(ctx context.Context, tx bun.IDB, sql string, args ...any) ([]*User, error) {
	records := []*User{}

	if err := tx.NewRaw(sql, args...).Scan(ctx, &records); err != nil {
		return records, err
	}

	return records, nil
}

func (a *users) Get(ctx context.Context, criteria ...repository.SelectCriteria) (*User, error) {
	record := &User{}

	q := a.db.NewSelect().
		Model(record)

	for _, c := range criteria {
		q.Apply(c)
	}

	if err := q.Limit(1).Scan(ctx); err != nil {
		return nil, err
	}

	return record, nil
}

func (a *users) GetByID(ctx context.Context, id string, criteria ...repository.SelectCriteria) (*User, error) {
	criteria = append([]repository.SelectCriteria{
		repository.SelectByID(id),
	}, criteria...)

	return a.Get(ctx, criteria...)
}

func (a *users) CreateTx(ctx context.Context, tx bun.IDB, record *User) (*User, error) {

	if record.Role == "" {
		record.Role = RoleGuest
	}

	if record.ID == uuid.Nil {
		record.ID = uuid.New()
	}

	_, err := tx.NewInsert().Model(record).Returning("*").Exec(ctx)
	return record, err
}

func (a *users) RegisterTx(ctx context.Context, tx bun.IDB, user *User) (*User, error) {
	_, err := tx.NewInsert().Model(user).Returning("*").Exec(ctx)
	return user, err
}

func (a *users) Register(ctx context.Context, user *User) (*User, error) {
	return a.RegisterTx(ctx, a.db, user)
}

func (a *users) GetByIdentifier(ctx context.Context, identifier string) (*User, error) {
	return a.GetByIdentifierTx(ctx, a.db, identifier)
}

func (a *users) GetByIdentifierTx(ctx context.Context, tx bun.IDB, identifier string) (*User, error) {
	column := "username"
	if isEmail(identifier) {
		column = "email"
	} else if isUUID(identifier) {
		column = "id"
	}

	record := &User{}
	q := tx.NewSelect().
		Model(record).
		Where(fmt.Sprintf("?TableAlias.%s %s ?", column, "="), identifier).
		Limit(1)

	var err error
	found := 0

	if found, err = q.ScanAndCount(ctx); err != nil {
		return nil, err
	}

	if found == 0 {
		return nil, repository.NewRecordNotFound().
			WithMetadata(map[string]any{
				"column":      column,
				"identfifier": identifier,
			})
	}

	return record, nil
}

func (a *users) ResetPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	return a.ResetPasswordTx(ctx, a.db, id, passwordHash)
}

func (a *users) ResetPasswordTx(ctx context.Context, tx bun.IDB, id uuid.UUID, passwordHash string) error {
	res, err := a.RawTx(ctx, tx, ResetUserPasswordSQL, passwordHash, id.String())
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

	_, err := a.UpdateTx(ctx, a.db, record, criteria...)

	return err
}

func (a *users) Update(ctx context.Context, record *User, criteria ...repository.UpdateCriteria) (*User, error) {
	return a.UpdateTx(ctx, a.db, record, criteria...)
}

func (a *users) UpdateTx(ctx context.Context, tx bun.IDB, record *User, criteria ...repository.UpdateCriteria) (*User, error) {
	q := tx.NewUpdate().
		Model(record)

	for _, c := range criteria {
		q.Apply(c)
	}

	res, err := q.
		OmitZero().
		WherePK().
		Returning("*").
		Exec(ctx)

	if err != nil {
		return nil, err
	}

	if err = repository.SQLExpectedCount(res, 1); err != nil {
		return nil, err
	}

	return record, nil
}

func (a *users) Upsert(ctx context.Context, record *User, criteria ...repository.UpdateCriteria) (*User, error) {
	return a.UpsertTx(ctx, a.db, record, criteria...)
}

func (a *users) UpsertTx(ctx context.Context, tx bun.IDB, record *User, criteria ...repository.UpdateCriteria) (*User, error) {
	identifier := record.Email
	if record.ID != uuid.Nil {
		identifier = record.ID.String()
	}

	user, err := a.GetByIdentifierTx(ctx, tx, identifier)
	if err == nil {
		record.ID = user.ID
		return a.UpdateTx(ctx, tx, record, criteria...)
	}

	// If we did not find a record, we will create it
	// but if it is a different error, then eject.
	if !repository.IsRecordNotFound(err) {
		return nil, err
	}

	return a.RegisterTx(ctx, tx, record)
}

func (a *users) GetOrRegisterTx(ctx context.Context, tx bun.IDB, record *User) (*User, error) {
	identifier := record.Email
	if record.ID != uuid.Nil {
		identifier = record.ID.String()
	}

	user, err := a.GetByIdentifierTx(ctx, tx, identifier)
	if err == nil {
		return user, nil
	}

	// If we did not find a record, we will create it
	// but if it is a different error, then eject.
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

	fmt.Printf("get by identifier: %s", identifier)
	user, err := a.GetByIdentifierTx(ctx, tx, identifier)
	if err == nil {
		return user, nil
	}

	if !repository.IsRecordNotFound(err) {
		return nil, err
	}

	return a.CreateTx(ctx, tx, record)
}

func isEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func isUUID(identifier string) bool {
	_, err := uuid.Parse(identifier)
	return err == nil
}

func isPhone(identifier string) bool {
	_, err := phonenumbers.Parse(identifier, "")
	return err == nil
}
