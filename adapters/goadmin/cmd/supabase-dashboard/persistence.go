package main

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"time"

	auth "github.com/goliatone/go-auth"
	authrepo "github.com/goliatone/go-auth/repository"
	persistence "github.com/goliatone/go-persistence-bun"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

type persistenceConfig struct{}

func (persistenceConfig) GetDebug() bool                { return false }
func (persistenceConfig) GetDriver() string             { return "sqlite" }
func (persistenceConfig) GetServer() string             { return "file" }
func (persistenceConfig) GetPingTimeout() time.Duration { return 5 * time.Second }
func (persistenceConfig) GetOtelIdentifier() string     { return "supabase-dashboard-example" }
func (persistenceConfig) GetMigrationsEnabled() bool    { return true }
func (persistenceConfig) GetSeedsEnabled() bool         { return false }

type persistenceRuntime struct {
	SQL         *sql.DB
	DB          *bun.DB
	Users       auth.Users
	Identifiers *authrepo.IdentifierStore
}

func openPersistence(ctx context.Context, dsn string) (persistenceRuntime, error) {
	sqlDB, err := sql.Open(sqliteshim.ShimName, dsn)
	if err != nil {
		return persistenceRuntime{}, fmt.Errorf("open SQLite: %w", err)
	}
	ready := false
	defer func() {
		if !ready {
			_ = sqlDB.Close()
		}
	}()

	persistence.RegisterModel((*auth.User)(nil))
	persistence.RegisterModel((*auth.PasswordReset)(nil))
	client, err := persistence.New(persistenceConfig{}, sqlDB, sqlitedialect.New())
	if err != nil {
		return persistenceRuntime{}, fmt.Errorf("construct persistence: %w", err)
	}
	migrations, err := fs.Sub(auth.GetMigrationsFS(), "data/sql/migrations")
	if err != nil {
		return persistenceRuntime{}, fmt.Errorf("resolve go-auth migrations: %w", err)
	}
	client.RegisterDialectMigrations(
		migrations,
		persistence.WithDialectSourceLabel("go-auth/data/sql/migrations"),
		persistence.WithValidationTargets("postgres", "sqlite"),
	)
	if err := client.ValidateDialects(ctx); err != nil {
		return persistenceRuntime{}, fmt.Errorf("validate migrations: %w", err)
	}
	if err := client.Migrate(ctx); err != nil {
		return persistenceRuntime{}, fmt.Errorf("apply migrations: %w", err)
	}

	runtime := persistenceRuntime{
		SQL:         sqlDB,
		DB:          client.DB(),
		Users:       auth.NewUsersRepository(client.DB()),
		Identifiers: authrepo.NewIdentifierStore(client.DB()),
	}
	ready = true
	return runtime, nil
}

func (r persistenceRuntime) Close() error {
	if r.SQL == nil {
		return nil
	}
	return r.SQL.Close()
}

type userTracker struct {
	users auth.Users
}

func (t userTracker) GetByIdentifier(ctx context.Context, identifier string) (*auth.User, error) {
	return t.users.GetByIdentifier(ctx, identifier)
}

func (t userTracker) TrackAttemptedLogin(ctx context.Context, user *auth.User) error {
	return t.users.TrackAttemptedLogin(ctx, user)
}

func (t userTracker) TrackSucccessfulLogin(ctx context.Context, user *auth.User) error {
	return t.users.TrackSucccessfulLogin(ctx, user)
}

func (t userTracker) ReserveLoginAttempt(ctx context.Context, userID uuid.UUID, policy auth.LoginAttemptPolicy) (auth.LoginAttemptReservation, error) {
	return t.users.(auth.AtomicLoginAttemptTracker).ReserveLoginAttempt(ctx, userID, policy)
}
