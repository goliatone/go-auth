package main

import (
	"context"
	"database/sql"
	"io"
	"path/filepath"
	"testing"

	exampleconfig "github.com/goliatone/go-auth-examples/config"
	gconfig "github.com/goliatone/go-config/config"
	"github.com/goliatone/go-logger/glog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithPersistenceMigratesAndSeedsFreshAndExistingSQLite(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "example.db") + "?cache=shared"

	openApp := func() *App {
		base := &exampleconfig.BaseConfig{
			Persistence: exampleconfig.Persistence{
				Debug:                 false,
				Driver:                "sqlite",
				Server:                "file",
				DSN:                   dsn,
				PingTimeoutExpression: "10s",
				OtelIdentifier:        "example-test",
			},
		}
		return &App{
			config: gconfig.New(base),
			logger: glog.NewLogger(
				glog.WithLoggerTypeJSON(),
				glog.WithWriter(io.Discard),
			),
		}
	}

	assertSeeded := func(app *App) {
		t.Helper()
		require.NotNil(t, app.bunDB)
		require.NotNil(t, app.repo)

		var count int
		require.NoError(t, app.bunDB.QueryRowContext(
			context.Background(),
			`SELECT COUNT(*) FROM users`,
		).Scan(&count))
		assert.Equal(t, 2, count)

		rows, err := app.bunDB.QueryContext(
			context.Background(),
			`SELECT external_id_provider, external_id FROM users ORDER BY username`,
		)
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, rows.Close())
		}()
		for rows.Next() {
			var provider sql.NullString
			var externalID sql.NullString
			require.NoError(t, rows.Scan(&provider, &externalID))
			assert.False(t, provider.Valid)
			assert.False(t, externalID.Valid)
		}
		require.NoError(t, rows.Err())
	}

	first := openApp()
	require.NoError(t, WithPersistence(context.Background(), first))
	assertSeeded(first)
	require.NoError(t, first.bunDB.Close())

	second := openApp()
	require.NoError(t, WithPersistence(context.Background(), second))
	assertSeeded(second)
	require.NoError(t, second.bunDB.Close())
}
