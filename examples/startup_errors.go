package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gerrors "github.com/goliatone/go-errors"
)

const (
	startupCodeConfigLoad            = "EXAMPLE_CONFIG_LOAD_FAILED"
	startupCodePersistenceOpen       = "EXAMPLE_PERSISTENCE_OPEN_FAILED"
	startupCodePersistenceConstruct  = "EXAMPLE_PERSISTENCE_CONSTRUCT_FAILED"
	startupCodeMigrationSource       = "EXAMPLE_MIGRATION_SOURCE_FAILED"
	startupCodeMigrationValidation   = "EXAMPLE_MIGRATION_VALIDATION_FAILED"
	startupCodeMigrationApply        = "EXAMPLE_MIGRATION_APPLY_FAILED"
	startupCodeFixtureSeed           = "EXAMPLE_FIXTURE_SEED_FAILED"
	startupCodeHTTPServerConstruct   = "EXAMPLE_HTTP_SERVER_CONSTRUCT_FAILED"
	startupCodeHTTPAuthConstruct     = "EXAMPLE_HTTP_AUTH_CONSTRUCT_FAILED"
	startupCodeHTTPServerServe       = "EXAMPLE_HTTP_SERVER_SERVE_FAILED"
	startupCodeAssetPrefixInvalid    = "EXAMPLE_ASSET_PREFIX_INVALID"
	startupDiagnosticFallbackMessage = "example startup failed"
)

var startupMessages = map[string]string{
	startupCodeConfigLoad:           "load example configuration",
	startupCodePersistenceOpen:      "open example database",
	startupCodePersistenceConstruct: "initialize example persistence",
	startupCodeMigrationSource:      "load embedded example migrations",
	startupCodeMigrationValidation:  "validate example migrations",
	startupCodeMigrationApply:       "apply example database migrations",
	startupCodeFixtureSeed:          "seed example database fixtures",
	startupCodeHTTPServerConstruct:  "initialize example HTTP server",
	startupCodeHTTPAuthConstruct:    "initialize example authentication",
	startupCodeHTTPServerServe:      "start example HTTP server",
	startupCodeAssetPrefixInvalid:   "configure views.url_prefix with a non-root namespace such as assets",
}

func startupFailure(stage, textCode string, cause error) error {
	if cause == nil {
		return nil
	}
	message := startupMessages[textCode]
	if message == "" {
		message = startupDiagnosticFallbackMessage
	}
	return gerrors.Wrap(cause, gerrors.CategoryOperation, message).
		WithTextCode(textCode).
		WithMetadata(map[string]any{"stage": stage})
}

func startupDiagnosticRenderer() (*gerrors.Renderer, error) {
	return gerrors.NewRenderer(
		gerrors.OutputDiagnostic,
		gerrors.WithMetadataAllowlist("stage", "file"),
		gerrors.WithMessageResolver(func(_ gerrors.OutputContext, input gerrors.MessageInput) (string, error) {
			if message := startupMessages[input.TextCode]; message != "" {
				return message, nil
			}
			return startupDiagnosticFallbackMessage, nil
		}),
		gerrors.WithSourceSanitizer(func(input gerrors.SourceInput) (string, error) {
			// SQLite constraint diagnostics contain schema identifiers, not
			// submitted credentials. Other source types remain type-only.
			if input.Type == "*sqlite.Error" || input.Type == "sqlite3.Error" {
				return input.Text, nil
			}
			return input.Type, nil
		}),
		gerrors.WithPathSanitizer(func(value string) (string, error) {
			return filepath.Base(value), nil
		}),
	)
}

func formatStartupDiagnostic(err error) string {
	if err == nil {
		return ""
	}
	renderer, buildErr := startupDiagnosticRenderer()
	if buildErr != nil {
		return startupDiagnosticFallbackMessage
	}

	chain := []error{err}
	chain = append(chain, errorLeaves(err, 0)...)
	rendered := make([]string, 0, len(chain))
	for _, current := range chain {
		output, renderErr := renderer.FormatDiagnostic(current)
		if output != "" && output != "null" {
			rendered = append(rendered, output)
		}
		if renderErr != nil {
			rendered = append(rendered, `{"message":"diagnostic sanitization failed"}`)
		}
	}
	return strings.Join(rendered, "\ncaused by: ")
}

func errorLeaves(err error, depth int) []error {
	if err == nil || depth >= 32 {
		return nil
	}
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		var leaves []error
		for _, cause := range multi.Unwrap() {
			leaves = append(leaves, errorLeaves(cause, depth+1)...)
		}
		return leaves
	}
	if single, ok := err.(interface{ Unwrap() error }); ok {
		if cause := single.Unwrap(); cause != nil {
			return errorLeaves(cause, depth+1)
		}
	}
	return []error{err}
}

func exitStartup(err error) {
	_, _ = fmt.Fprintln(os.Stderr, formatStartupDiagnostic(err))
	os.Exit(1)
}
