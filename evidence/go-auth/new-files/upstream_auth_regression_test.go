package auth_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	gerrors "github.com/goliatone/go-errors"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
)

func upstreamSQLUser(t *testing.T) (*bun.DB, auth.Users, *auth.User) {
	t.Helper()
	var db *bun.DB
	if dsn := os.Getenv("GO_AUTH_TEST_POSTGRES_DSN"); dsn != "" {
		admin, err := sql.Open("postgres", dsn)
		require.NoError(t, err)
		schema := "auth_" + uuid.New().String()[:8]
		_, err = admin.Exec(`CREATE SCHEMA ` + schema)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
			require.NoError(t, err)
			require.NoError(t, admin.Close())
		})
		raw, err := sql.Open("postgres", dsn+" search_path="+schema)
		require.NoError(t, err)
		db = bun.NewDB(raw, pgdialect.New())
	} else {
		raw, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "auth.db")+"?_busy_timeout=5000&_journal_mode=WAL")
		require.NoError(t, err)
		db = bun.NewDB(raw, sqlitedialect.New())
	}
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	_, err := db.NewCreateTable().Model((*auth.User)(nil)).Exec(context.Background())
	require.NoError(t, err)
	hash, err := auth.HashPassword("synthetic-password")
	require.NoError(t, err)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	users := auth.NewUsersRepository(db)
	user, err := users.Create(context.Background(), &auth.User{
		ID: uuid.New(), Email: "user@example.invalid", Username: "user-a", Role: auth.RoleMember,
		Status: auth.UserStatusActive, FirstName: "User", LastName: "A", PasswordHash: hash,
		EmailValidated: true, ExternalID: "opaque-a", ExternalIDProvider: "example", Phone: "000",
		ProfilePicture: "opaque-picture", Metadata: map[string]any{"opaque": "payload"}, ResetedAt: &at,
		CreatedAt: &at, UpdatedAt: &at,
	})
	require.NoError(t, err)
	return db, users, user
}

func assertUpstreamIdentity(t *testing.T, before, after *auth.User) {
	t.Helper()
	require.Equal(t, before.Email, after.Email, "email changed")
	require.Equal(t, before.Username, after.Username, "username changed")
	require.Equal(t, before.Role, after.Role, "role changed")
	require.Equal(t, before.PasswordHash, after.PasswordHash, "password hash changed")
	require.Equal(t, before.FirstName, after.FirstName)
	require.Equal(t, before.LastName, after.LastName)
	require.Equal(t, before.ExternalID, after.ExternalID)
	require.Equal(t, before.ExternalIDProvider, after.ExternalIDProvider)
	require.Equal(t, before.Metadata, after.Metadata)
	require.Equal(t, before.ResetedAt, after.ResetedAt)
	require.Equal(t, before.CreatedAt, after.CreatedAt)
}

func TestUpstreamStatusMutationPreservesCredentials(t *testing.T) {
	_, users, before := upstreamSQLUser(t)
	ctx := context.Background()
	for _, status := range []auth.UserStatus{auth.UserStatusSuspended, auth.UserStatusActive, auth.UserStatusDisabled} {
		after, err := users.UpdateStatus(ctx, before.ID, status)
		require.NoError(t, err)
		require.Equal(t, status, after.Status)
		assertUpstreamIdentity(t, before, after)
		persisted, err := users.GetByID(ctx, before.ID.String())
		require.NoError(t, err)
		assertUpstreamIdentity(t, before, persisted)
	}
}

func TestUpstreamStatusOptionsAndRollback(t *testing.T) {
	db, users, before := upstreamSQLUser(t)
	ctx := context.Background()
	stamp := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	after, err := users.UpdateStatus(ctx, before.ID, auth.UserStatusSuspended, nil, auth.WithSuspendedAt(&stamp))
	require.NoError(t, err)
	assertUpstreamIdentity(t, before, after)
	require.Equal(t, stamp, *after.SuspendedAt)
	after, err = users.UpdateStatus(ctx, before.ID, auth.UserStatusActive, auth.WithSuspendedAt(nil), func(u *auth.User) {
		u.Phone = ""
		u.EmailValidated = false
		u.ResetedAt = nil
		u.Metadata["opaque"] = "changed"
	})
	require.NoError(t, err)
	require.Nil(t, after.SuspendedAt)
	require.Nil(t, after.ResetedAt)
	require.Empty(t, after.Phone)
	require.False(t, after.EmailValidated)
	require.Equal(t, "changed", after.Metadata["opaque"])
	require.Equal(t, before.PasswordHash, after.PasswordHash)
	rollback := errors.New("rollback fixture")
	err = db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		changed, e := users.UpdateStatusTx(ctx, tx, before.ID, auth.UserStatusDisabled, auth.WithSuspendedAt(&stamp))
		require.NoError(t, e)
		require.Equal(t, auth.UserStatusDisabled, changed.Status)
		return rollback
	})
	require.ErrorIs(t, err, rollback)
	persisted, err := users.GetByID(ctx, before.ID.String())
	require.NoError(t, err)
	require.Equal(t, after, persisted)
	_, err = users.UpdateStatus(ctx, uuid.New(), auth.UserStatusDisabled)
	require.Error(t, err)
}

type upstreamTracker struct{ auth.Users }

func (u upstreamTracker) GetByIdentifier(ctx context.Context, id string) (*auth.User, error) {
	return u.Users.GetByIdentifier(ctx, id)
}
func (u upstreamTracker) ReserveLoginAttempt(ctx context.Context, id uuid.UUID, p auth.LoginAttemptPolicy) (auth.LoginAttemptReservation, error) {
	return u.Users.(auth.AtomicLoginAttemptRepository).ReserveLoginAttempt(ctx, id, p)
}

func TestUpstreamUserLifecycleReauthentication(t *testing.T) {
	_, users, before := upstreamSQLUser(t)
	ctx := context.Background()
	a := auth.NewAuthenticator(auth.NewUserProvider(upstreamTracker{users}), newMockConfig())
	token, err := a.Login(ctx, before.Email, "synthetic-password")
	require.NoError(t, err)
	require.NotEmpty(t, token)
	suspended, err := users.Suspend(ctx, auth.ActorRef{Type: "system"}, before)
	require.NoError(t, err)
	require.NotNil(t, suspended.SuspendedAt)
	_, err = a.Login(ctx, before.Email, "synthetic-password")
	require.ErrorIs(t, err, auth.ErrUserSuspended)
	active, err := users.Reinstate(ctx, auth.ActorRef{Type: "system"}, suspended)
	require.NoError(t, err)
	require.Nil(t, active.SuspendedAt)
	token, err = a.Login(ctx, before.Email, "synthetic-password")
	require.NoError(t, err)
	require.NotEmpty(t, token)
	_, err = auth.NewUserStateMachine(users).Transition(ctx, auth.ActorRef{Type: "system"}, active, auth.UserStatusDisabled)
	require.NoError(t, err)
	_, err = a.Login(ctx, before.Email, "synthetic-password")
	require.ErrorIs(t, err, auth.ErrUserDisabled)
	persisted, err := users.GetByID(ctx, before.ID.String())
	require.NoError(t, err)
	assertUpstreamIdentity(t, before, persisted)
}

func TestUpstreamMissingIdentityProvider(t *testing.T) {
	var pointer *MockIdentityProvider
	var function upstreamNilFuncProvider
	var mapProvider upstreamNilMapProvider
	for name, provider := range map[string]auth.IdentityProvider{"nil": nil, "pointer": pointer, "function": function, "map": mapProvider} {
		t.Run(name, func(t *testing.T) {
			a := auth.NewAuthenticator(provider, newMockConfig())
			var lookupErr error
			require.NotPanics(t, func() { _, lookupErr = a.IdentityFromSession(context.Background(), nil) })
			require.ErrorIs(t, lookupErr, auth.ErrIdentityProviderRequired)
			for _, call := range []func() (string, error){func() (string, error) { return a.Login(context.Background(), "user@example.invalid", "synthetic") }, func() (string, error) { return a.Impersonate(context.Background(), "user@example.invalid") }} {
				var token string
				var err error
				require.NotPanics(t, func() { token, err = call() })
				require.Empty(t, token)
				require.Error(t, err)
				var rich *gerrors.Error
				require.ErrorAs(t, err, &rich)
				require.ErrorIs(t, err, auth.ErrIdentityProviderRequired)
				require.Equal(t, gerrors.CategoryInternal, rich.Category)
				require.Equal(t, gerrors.CodeInternal, rich.Code)
				require.Equal(t, "IDENTITY_PROVIDER_REQUIRED", rich.TextCode)
			}
		})
	}
}

type upstreamNilFuncProvider func()

func (upstreamNilFuncProvider) VerifyIdentity(context.Context, string, string) (auth.Identity, error) {
	panic("nil function invoked")
}
func (upstreamNilFuncProvider) FindIdentityByIdentifier(context.Context, string) (auth.Identity, error) {
	panic("nil function invoked")
}

type upstreamNilMapProvider map[string]string

func (upstreamNilMapProvider) VerifyIdentity(context.Context, string, string) (auth.Identity, error) {
	panic("nil map invoked")
}
func (upstreamNilMapProvider) FindIdentityByIdentifier(context.Context, string) (auth.Identity, error) {
	panic("nil map invoked")
}

func TestUpstreamLiveAccountObservationClock(t *testing.T) {
	_, users, user := upstreamSQLUser(t)
	p, err := auth.NewAuthenticatedPrincipal(auth.AuthenticatedPrincipalInput{ApplicationSubject: user.ID.String(), Provider: "local", ProviderSubject: user.ID.String()})
	require.NoError(t, err)
	source := auth.AccountStateSourceFunc(func(ctx context.Context, p auth.AuthenticatedPrincipal) (auth.AccountStateObservation, error) {
		u, e := users.GetByID(ctx, p.ApplicationSubject())
		if e != nil {
			return auth.AccountStateObservation{}, e
		}
		return auth.AccountStateObservation{State: auth.AccountState(u.Status), ObservedAt: time.Now().UTC()}, nil
	})
	r, err := auth.NewCompositeAccountStateResolver(auth.CompositeAccountStateResolverConfig{Sources: []auth.NamedAccountStateSource{{Name: "local-sql", Source: source}}})
	require.NoError(t, err)
	result, err := r.ResolveCurrentAccountState(context.Background(), auth.AccountStateRequest{Principal: p, MaximumStaleness: time.Minute, Privileged: true})
	require.NoError(t, err)
	require.False(t, result.InvalidEvidence)
	require.Equal(t, auth.AccountStateActive, result.State)
}

// A zero-valued struct can be a valid provider; only nil-like values fail configuration.
type upstreamValueProvider struct{}

func (upstreamValueProvider) VerifyIdentity(context.Context, string, string) (auth.Identity, error) {
	return TestIdentity{id: "user-a", username: "user-a", email: "user@example.invalid", role: "member"}, nil
}
func (p upstreamValueProvider) FindIdentityByIdentifier(ctx context.Context, id string) (auth.Identity, error) {
	return p.VerifyIdentity(ctx, id, "")
}
func TestUpstreamValidZeroValueProvider(t *testing.T) {
	a := auth.NewAuthenticator(upstreamValueProvider{}, newMockConfig())
	token, err := a.Login(context.Background(), "user@example.invalid", "synthetic")
	require.NoError(t, err)
	require.NotEmpty(t, token)
	token, err = a.Impersonate(context.Background(), "user@example.invalid")
	require.NoError(t, err)
	require.NotEmpty(t, token)
	// Token-only consumers keep the legacy constructor and validation path.
	validator := auth.NewAuthenticator(nil, newMockConfig())
	_, err = validator.SessionFromToken(token)
	require.NoError(t, err)
}

type upstreamBeforeStatusUpdate struct {
	db  *bun.DB
	id  uuid.UUID
	ran bool
	err error
}

func (h *upstreamBeforeStatusUpdate) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	if _, ok := event.IQuery.(*bun.UpdateQuery); ok && !h.ran {
		h.ran = true
		_, h.err = h.db.ExecContext(ctx, `UPDATE users SET email = ?, password_hash = ? WHERE id = ?`, "changed@example.invalid", "changed-hash", h.id)
	}
	return ctx
}
func (*upstreamBeforeStatusUpdate) AfterQuery(context.Context, *bun.QueryEvent) {}

func TestUpstreamStatusOptionsDoNotOverwriteUnrelatedConcurrentWrite(t *testing.T) {
	db, users, before := upstreamSQLUser(t)
	hook := &upstreamBeforeStatusUpdate{db: db, id: before.ID}
	db.AddQueryHook(hook)
	after, err := users.UpdateStatus(context.Background(), before.ID, auth.UserStatusSuspended, func(u *auth.User) { u.Phone = "changed-phone" })
	require.NoError(t, err)
	require.NoError(t, hook.err)
	require.True(t, hook.ran)
	require.Equal(t, "changed@example.invalid", after.Email)
	require.Equal(t, "changed-hash", after.PasswordHash)
	require.Equal(t, "changed-phone", after.Phone)
}
