package auth

import (
	"embed"
	"io/fs"
)

//go:embed data/sql/migrations
var migrationsFS embed.FS

// coreMigrationsFS contains the canonical auth schema baseline (users +
// password_reset + user status). It intentionally excludes optional social/Auth0
// sync extras.
//
//go:embed data/sql/migration_tracks/core
var coreMigrationsFS embed.FS

// authExtrasMigrationsFS contains optional auth schema extras that extend the
// core user model (social accounts + Auth0 identifier mappings).
//
//go:embed data/sql/migration_tracks/auth_extras
var authExtrasMigrationsFS embed.FS

// GetMigrationsFS returns the migration files for this package
func GetMigrationsFS() fs.FS {
	return migrationsFS
}

// GetCoreMigrationsFS returns the canonical core auth schema migrations.
func GetCoreMigrationsFS() fs.FS {
	return mustSubFS(coreMigrationsFS, "data/sql/migration_tracks/core")
}

// GetAuthExtrasMigrationsFS returns optional auth extras migrations.
func GetAuthExtrasMigrationsFS() fs.FS {
	return mustSubFS(authExtrasMigrationsFS, "data/sql/migration_tracks/auth_extras")
}

func mustSubFS(root fs.FS, path string) fs.FS {
	sub, err := fs.Sub(root, path)
	if err != nil {
		panic("go-auth: failed to resolve embedded migrations sub-filesystem: " + err.Error())
	}
	return sub
}
