package main

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun/driver/sqliteshim"
)

func TestFormatStartupDiagnosticIncludesSafeSQLiteCause(t *testing.T) {
	db, err := sql.Open(sqliteshim.ShimName, "file:"+filepath.Join(t.TempDir(), "diagnostic.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(`CREATE TABLE example_unique (value TEXT NOT NULL UNIQUE)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO example_unique (value) VALUES ('duplicate')`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO example_unique (value) VALUES ('duplicate')`)
	require.Error(t, err)

	output := formatStartupDiagnostic(startupFailure(
		"persistence.fixtures.seed",
		startupCodeFixtureSeed,
		err,
	))
	assert.Contains(t, output, startupCodeFixtureSeed)
	assert.Contains(t, output, "seed example database fixtures")
	assert.Contains(t, output, "persistence.fixtures.seed")
	assert.Contains(t, output, "UNIQUE constraint failed")
	workingDir, workingDirErr := os.Getwd()
	require.NoError(t, workingDirErr)
	assert.NotContains(t, output, workingDir)
}

func TestFormatStartupDiagnosticDoesNotExposeArbitrarySourceText(t *testing.T) {
	const canary = "STARTUP-DATABASE-PASSWORD-CANARY"
	output := formatStartupDiagnostic(startupFailure(
		"persistence.open",
		startupCodePersistenceOpen,
		errors.New("password="+canary),
	))

	assert.Contains(t, output, startupCodePersistenceOpen)
	assert.Contains(t, output, "open example database")
	assert.NotContains(t, output, canary)
	assert.False(t, strings.Contains(output, "password="))
}

func TestFormatStartupDiagnosticExplainsInvalidAssetPrefix(t *testing.T) {
	_, cause := normalizeAssetURLPrefix("")
	require.Error(t, cause)

	output := formatStartupDiagnostic(startupFailure(
		"http.server.construct",
		startupCodeHTTPServerConstruct,
		cause,
	))

	assert.Contains(t, output, startupCodeHTTPServerConstruct)
	assert.Contains(t, output, startupCodeAssetPrefixInvalid)
	assert.Contains(t, output, "configure views.url_prefix")
	assert.NotContains(t, output, "example startup failed")
}
