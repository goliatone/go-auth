package auth

import (
	"embed"
)

//go:embed data/sql/migrations/*.sql
var migrationsFS embed.FS

// GetMigrationsFS returns the migration files for this package
func GetMigrationsFS() embed.FS {
	return migrationsFS
}
