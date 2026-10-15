package contract_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-users/adapter/goauth"
	"github.com/goliatone/go-users/pkg/types"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
)

type tracker struct{ auth.Users }

func (u tracker) GetByIdentifier(ctx context.Context, id string) (*auth.User, error) {
	return u.Users.GetByIdentifier(ctx, id)
}
func (u tracker) ReserveLoginAttempt(ctx context.Context, id uuid.UUID, p auth.LoginAttemptPolicy) (auth.LoginAttemptReservation, error) {
	return u.Users.(auth.AtomicLoginAttemptRepository).ReserveLoginAttempt(ctx, id, p)
}

func TestGoUsersAdapterLifecyclePreservesIdentity(t *testing.T) {
	ctx := context.Background()
	raw, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "adapter.db"))
	require.NoError(t, err)
	db := bun.NewDB(raw, sqlitedialect.New())
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	_, err = db.NewCreateTable().Model((*auth.User)(nil)).Exec(ctx)
	require.NoError(t, err)
	users := auth.NewUsersRepository(db)
	hash, err := auth.HashPassword("synthetic-password")
	require.NoError(t, err)
	before, err := users.Create(ctx, &auth.User{ID: uuid.New(), Email: "user@example.invalid", Username: "user-a", Role: auth.RoleMember, Status: auth.UserStatusActive, PasswordHash: hash})
	require.NoError(t, err)
	adapter := goauth.NewUsersAdapter(users)
	actor := types.ActorRef{ID: uuid.New(), Type: "system"}
	provider := auth.NewUserProvider(tracker{users})
	for _, state := range []types.LifecycleState{types.LifecycleStateSuspended, types.LifecycleStateActive, types.LifecycleStateDisabled} {
		returned, err := adapter.UpdateStatus(ctx, actor, before.ID, state)
		require.NoError(t, err)
		require.Equal(t, before.Email, returned.Email)
		require.Equal(t, before.Username, returned.Username)
		require.Equal(t, string(before.Role), returned.Role)
		after, err := users.GetByID(ctx, before.ID.String())
		require.NoError(t, err)
		require.Equal(t, before.Email, after.Email)
		require.Equal(t, before.Username, after.Username)
		require.Equal(t, before.Role, after.Role)
		require.Equal(t, before.PasswordHash, after.PasswordHash)
		_, err = provider.VerifyIdentity(ctx, before.Email, "synthetic-password")
		if state == types.LifecycleStateActive {
			require.NoError(t, err)
			require.Nil(t, after.SuspendedAt)
		} else {
			require.Error(t, err)
		}
		if state == types.LifecycleStateSuspended {
			require.NotNil(t, after.SuspendedAt)
		}
	}
}
