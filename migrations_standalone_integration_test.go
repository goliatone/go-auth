package auth_test

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"maps"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

func TestMigrationGettersExposeCoreAndExtras(t *testing.T) {
	t.Parallel()

	if _, err := fs.Sub(auth.GetCoreMigrationsFS(), "data/sql/migrations"); err != nil {
		t.Fatalf("core migrations fs missing root: %v", err)
	}
	if _, err := fs.Sub(auth.GetAuthExtrasMigrationsFS(), "data/sql/migrations"); err != nil {
		t.Fatalf("auth extras migrations fs missing root: %v", err)
	}
}

func TestSegmentedTracksMatchFullMigrationTree(t *testing.T) {
	t.Parallel()

	type dialectSpec struct {
		name string
		path string
	}
	dialects := []dialectSpec{
		{name: "postgres", path: "data/sql/migrations"},
		{name: "sqlite", path: "data/sql/migrations/sqlite"},
	}

	for _, dialect := range dialects {
		t.Run(dialect.name, func(t *testing.T) {
			fullFiles := mustReadMigrationFiles(t, auth.GetMigrationsFS(), dialect.path)
			coreFiles := mustReadMigrationFiles(t, auth.GetCoreMigrationsFS(), dialect.path)
			extraFiles := mustReadMigrationFiles(t, auth.GetAuthExtrasMigrationsFS(), dialect.path)

			merged := make(map[string]string, len(coreFiles)+len(extraFiles))
			maps.Copy(merged, coreFiles)
			for name, content := range extraFiles {
				if _, exists := merged[name]; exists {
					t.Fatalf("duplicate segmented migration %q in %s track", name, dialect.name)
				}
				merged[name] = content
			}

			if len(merged) != len(fullFiles) {
				t.Fatalf(
					"segmented/full file count mismatch for %s: segmented=%d full=%d",
					dialect.name,
					len(merged),
					len(fullFiles),
				)
			}

			for name, fullContent := range fullFiles {
				segmentedContent, exists := merged[name]
				if !exists {
					t.Fatalf("segmented tracks missing %s migration %q", dialect.name, name)
				}
				if segmentedContent != fullContent {
					t.Fatalf("segmented content mismatch for %s migration %q", dialect.name, name)
				}
			}
		})
	}
}

func TestStandaloneMigrationsSQLiteApplyRollbackReapply(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "auth.db")+"?_fk=1")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := applyStandalone(ctx, db, "sqlite"); err != nil {
		t.Fatalf("apply standalone sqlite: %v", err)
	}
	assertTableExistsSQLite(t, db, "users")
	assertTableExistsSQLite(t, db, "password_reset")
	assertTableExistsSQLite(t, db, "social_accounts")
	assertTableExistsSQLite(t, db, "user_identifiers")

	if err := rollbackStandalone(ctx, db, "sqlite"); err != nil {
		t.Fatalf("rollback standalone sqlite: %v", err)
	}
	assertTableNotExistsSQLite(t, db, "users")
	assertTableNotExistsSQLite(t, db, "password_reset")
	assertTableNotExistsSQLite(t, db, "social_accounts")
	assertTableNotExistsSQLite(t, db, "user_identifiers")

	if err := applyStandalone(ctx, db, "sqlite"); err != nil {
		t.Fatalf("reapply standalone sqlite: %v", err)
	}
	assertTableExistsSQLite(t, db, "users")
	assertTableExistsSQLite(t, db, "password_reset")
	assertTableExistsSQLite(t, db, "social_accounts")
	assertTableExistsSQLite(t, db, "user_identifiers")
}

func TestStandaloneMigrationsPostgresApplyRollbackReapply(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("GO_AUTH_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set GO_AUTH_TEST_POSTGRES_DSN to run postgres integration migration test")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	schemaName := fmt.Sprintf("goauth_mig_%d_%d", time.Now().UnixNano(), rand.Intn(10000))
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA "`+schemaName+`"`); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `SET search_path TO public`)
		_, _ = db.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS "`+schemaName+`" CASCADE`)
	})
	if _, err := db.ExecContext(ctx, `SET search_path TO "`+schemaName+`"`); err != nil {
		t.Fatalf("set search path: %v", err)
	}

	if err := applyStandalone(ctx, db, "postgres"); err != nil {
		t.Fatalf("apply standalone postgres: %v", err)
	}
	assertTableExistsPostgres(t, db, schemaName, "users")
	assertTableExistsPostgres(t, db, schemaName, "password_reset")
	assertTableExistsPostgres(t, db, schemaName, "social_accounts")
	assertTableExistsPostgres(t, db, schemaName, "user_identifiers")

	if err := rollbackStandalone(ctx, db, "postgres"); err != nil {
		t.Fatalf("rollback standalone postgres: %v", err)
	}
	assertTableNotExistsPostgres(t, db, schemaName, "users")
	assertTableNotExistsPostgres(t, db, schemaName, "password_reset")
	assertTableNotExistsPostgres(t, db, schemaName, "social_accounts")
	assertTableNotExistsPostgres(t, db, schemaName, "user_identifiers")

	if err := applyStandalone(ctx, db, "postgres"); err != nil {
		t.Fatalf("reapply standalone postgres: %v", err)
	}
	assertTableExistsPostgres(t, db, schemaName, "users")
	assertTableExistsPostgres(t, db, schemaName, "password_reset")
	assertTableExistsPostgres(t, db, schemaName, "social_accounts")
	assertTableExistsPostgres(t, db, schemaName, "user_identifiers")
}

func applyStandalone(ctx context.Context, db *sql.DB, dialect string) error {
	if err := applyMigrationTrack(ctx, db, auth.GetCoreMigrationsFS(), dialect, true); err != nil {
		return fmt.Errorf("apply core migrations: %w", err)
	}
	if err := applyMigrationTrack(ctx, db, auth.GetAuthExtrasMigrationsFS(), dialect, true); err != nil {
		return fmt.Errorf("apply auth extras migrations: %w", err)
	}
	return nil
}

func rollbackStandalone(ctx context.Context, db *sql.DB, dialect string) error {
	if err := applyMigrationTrack(ctx, db, auth.GetAuthExtrasMigrationsFS(), dialect, false); err != nil {
		return fmt.Errorf("rollback auth extras migrations: %w", err)
	}
	if err := applyMigrationTrack(ctx, db, auth.GetCoreMigrationsFS(), dialect, false); err != nil {
		return fmt.Errorf("rollback core migrations: %w", err)
	}
	return nil
}

func applyMigrationTrack(ctx context.Context, db *sql.DB, source fs.FS, dialect string, up bool) error {
	subdir := "data/sql/migrations"
	if strings.EqualFold(strings.TrimSpace(dialect), "sqlite") {
		subdir = "data/sql/migrations/sqlite"
	}
	root, err := fs.Sub(source, subdir)
	if err != nil {
		return err
	}

	pattern := "*.up.sql"
	if !up {
		pattern = "*.down.sql"
	}
	files, err := fs.Glob(root, pattern)
	if err != nil {
		return err
	}
	sort.Strings(files)
	if !up {
		for i, j := 0, len(files)-1; i < j; i, j = i+1, j-1 {
			files[i], files[j] = files[j], files[i]
		}
	}

	for _, file := range files {
		raw, err := fs.ReadFile(root, file)
		if err != nil {
			return err
		}
		statements := splitSQLStatements(string(raw))
		for _, stmt := range statements {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("exec %s statement %q: %w", file, stmt, err)
			}
		}
	}
	return nil
}

func splitSQLStatements(sqlText string) []string {
	parts := strings.Split(sqlText, "---bun:split")
	statements := make([]string, 0, len(parts)*2)
	for _, part := range parts {
		chunks := strings.SplitSeq(part, ";")
		for chunk := range chunks {
			stmt := strings.TrimSpace(chunk)
			if stmt == "" {
				continue
			}
			if isCommentOnly(stmt) {
				continue
			}
			statements = append(statements, stmt)
		}
	}
	return statements
}

func mustReadMigrationFiles(t *testing.T, source fs.FS, subdir string) map[string]string {
	t.Helper()

	root, err := fs.Sub(source, subdir)
	if err != nil {
		t.Fatalf("resolve migrations subdir %q: %v", subdir, err)
	}

	files, err := fs.Glob(root, "*.sql")
	if err != nil {
		t.Fatalf("glob migrations in %q: %v", subdir, err)
	}
	if len(files) == 0 {
		t.Fatalf("expected migration files in %q", subdir)
	}
	sort.Strings(files)

	output := make(map[string]string, len(files))
	for _, file := range files {
		content, err := fs.ReadFile(root, file)
		if err != nil {
			t.Fatalf("read migration %s/%s: %v", subdir, file, err)
		}
		output[file] = string(content)
	}
	return output
}

func isCommentOnly(input string) bool {
	lines := strings.Split(input, "\n")
	nonComment := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") || trimmed == "" {
			continue
		}
		nonComment = append(nonComment, trimmed)
	}
	return len(nonComment) == 0
}

func assertTableExistsSQLite(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
	if err != nil || name != table {
		t.Fatalf("expected sqlite table %q to exist, err=%v", table, err)
	}
}

func assertTableNotExistsSQLite(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
	if err == nil {
		t.Fatalf("expected sqlite table %q to be absent", table)
	}
}

func assertTableExistsPostgres(t *testing.T, db *sql.DB, schema, table string) {
	t.Helper()
	var exists bool
	err := db.QueryRow(
		`SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables
			WHERE table_schema = $1 AND table_name = $2
		)`,
		schema,
		table,
	).Scan(&exists)
	if err != nil || !exists {
		t.Fatalf("expected postgres table %s.%s to exist, err=%v", schema, table, err)
	}
}

func assertTableNotExistsPostgres(t *testing.T, db *sql.DB, schema, table string) {
	t.Helper()
	var exists bool
	err := db.QueryRow(
		`SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables
			WHERE table_schema = $1 AND table_name = $2
		)`,
		schema,
		table,
	).Scan(&exists)
	if err != nil {
		t.Fatalf("query postgres table existence %s.%s: %v", schema, table, err)
	}
	if exists {
		t.Fatalf("expected postgres table %s.%s to be absent", schema, table)
	}
}
