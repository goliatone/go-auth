package repository

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/goliatone/go-auth/social"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"

	_ "github.com/mattn/go-sqlite3"
)

const (
	sqliteCreateUsers          = "CREATE TABLE users (id TEXT NOT NULL PRIMARY KEY);"
	sqliteCreateSocialAccounts = `CREATE TABLE social_accounts (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    email TEXT,
    name TEXT,
    username TEXT,
    avatar_url TEXT,
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMP NULL,
    profile_data TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT uq_social_accounts_provider_id UNIQUE (provider, provider_user_id),
    CONSTRAINT uq_social_accounts_user_provider UNIQUE (user_id, provider)
);`
)

func setupSocialAccountRepo(t *testing.T) (*SocialAccountRepository, string, func()) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)

	bunDB := bun.NewDB(db, sqlitedialect.New())

	_, err = bunDB.Exec("PRAGMA foreign_keys = ON;")
	require.NoError(t, err)

	_, err = bunDB.Exec(sqliteCreateUsers)
	require.NoError(t, err)
	_, err = bunDB.Exec(sqliteCreateSocialAccounts)
	require.NoError(t, err)

	userID := uuid.New().String()
	_, err = bunDB.Exec("INSERT INTO users (id) VALUES (?)", userID)
	require.NoError(t, err)

	cleanup := func() {
		_ = bunDB.Close()
		_ = db.Close()
	}

	return NewSocialAccountRepository(bunDB), userID, cleanup
}

func TestSocialAccountRepositoryUpsertAndFind(t *testing.T) {
	repo, userID, cleanup := setupSocialAccountRepo(t)
	defer cleanup()

	ctx := context.Background()
	expiresAt := time.Now().Add(2 * time.Hour).UTC()

	account := &social.SocialAccount{
		UserID:         userID,
		Provider:       "github",
		ProviderUserID: "123",
		Email:          "octo@example.com",
		Name:           "Octo Cat",
		Username:       "octo",
		AvatarURL:      "https://example.com/avatar.png",
		AccessToken:    "token",
		RefreshToken:   "refresh",
		TokenExpiresAt: &expiresAt,
		ProfileData:    map[string]any{"plan": "pro"},
	}

	err := repo.Upsert(ctx, account)
	require.NoError(t, err)

	found, err := repo.FindByProviderID(ctx, "github", "123")
	require.NoError(t, err)
	assert.Equal(t, userID, found.UserID)
	assert.Equal(t, "octo@example.com", found.Email)
	assert.Equal(t, "octo", found.Username)
	assert.Equal(t, "token", found.AccessToken)
	assert.Equal(t, "refresh", found.RefreshToken)
	require.NotNil(t, found.TokenExpiresAt)
	assert.WithinDuration(t, expiresAt, *found.TokenExpiresAt, time.Second)
	assert.Equal(t, "pro", found.ProfileData["plan"])

	account.Email = "new@example.com"
	account.Username = "octo-new"
	account.ProfileData = map[string]any{"plan": "enterprise"}

	err = repo.Upsert(ctx, account)
	require.NoError(t, err)

	updated, err := repo.FindByProviderID(ctx, "github", "123")
	require.NoError(t, err)
	assert.Equal(t, "new@example.com", updated.Email)
	assert.Equal(t, "octo-new", updated.Username)
	assert.Equal(t, "enterprise", updated.ProfileData["plan"])

	accounts, err := repo.FindByUserID(ctx, userID)
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	assert.Equal(t, updated.ID, accounts[0].ID)
}

func TestSocialAccountRepositoryDelete(t *testing.T) {
	repo, userID, cleanup := setupSocialAccountRepo(t)
	defer cleanup()

	ctx := context.Background()
	account := &social.SocialAccount{
		UserID:         userID,
		Provider:       "google",
		ProviderUserID: "abc",
		Email:          "user@example.com",
		ProfileData:    map[string]any{},
	}

	err := repo.Upsert(ctx, account)
	require.NoError(t, err)

	found, err := repo.FindByProviderID(ctx, "google", "abc")
	require.NoError(t, err)
	require.NotEmpty(t, found.ID)

	err = repo.Delete(ctx, found.ID)
	require.NoError(t, err)

	_, err = repo.FindByProviderID(ctx, "google", "abc")
	require.Error(t, err)
	assert.ErrorIs(t, err, sql.ErrNoRows)
}

func TestSocialAccountRepositoryDeleteByUserAndProvider(t *testing.T) {
	repo, userID, cleanup := setupSocialAccountRepo(t)
	defer cleanup()

	ctx := context.Background()
	account := &social.SocialAccount{
		UserID:         userID,
		Provider:       "github",
		ProviderUserID: "321",
		Email:          "user@example.com",
		ProfileData:    map[string]any{},
	}

	err := repo.Upsert(ctx, account)
	require.NoError(t, err)

	err = repo.DeleteByUserAndProvider(ctx, userID, "github")
	require.NoError(t, err)

	_, err = repo.FindByProviderID(ctx, "github", "321")
	require.Error(t, err)
	assert.ErrorIs(t, err, sql.ErrNoRows)
}
