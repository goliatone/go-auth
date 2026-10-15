# Development and CI/CD Guide

This guide defines the Go quality workflow for the root module, feature-gate
adapter, go-admin adapter, and examples.

## Quality model

The repository uses:

- `gofmt` for formatting
- `go test` and the race detector for tests
- `golangci-lint` for correctness and maintainability checks
- `govulncheck` and `gosec` for security checks

The canonical workflow files are:

- `.golangci.yml`
- `.golangci-lint-version`
- `.github/workflows/go-quality.yml`
- `taskfile`
- `tools/quality/baseline.sh`

The taskfile creates `.tmp/go.work` for development checks. Each module check
pairs that module with the root checkout. Root checks use only the root module,
so dependencies from adapters and examples cannot change the root dependency
graph.

It is temporary and must not be used as release evidence. Publication checks
run each module with `GOWORK=off` against the intended public dependency graph.

## Local setup

Install the pinned quality tools:

```bash
./taskfile go:tools:all
```

This installs the repository versions of `golangci-lint`, `govulncheck`, and
`gosec`. Lint commands verify the installed `golangci-lint` version and replace
an incompatible binary.

## Day-to-day workflow

Run focused tests while developing, then use:

```bash
./taskfile go:fmt
./taskfile go:quality:pr
```

`go:quality:pr` is non-mutating and runs:

- formatting verification
- tests in all configured modules
- change-scoped linting relative to `origin/main`

Fetch the comparison branch before using incremental lint:

```bash
git fetch origin main
```

Override the comparison revision when needed:

```bash
GO_LINT_NEW_FROM_REV=HEAD~1 ./taskfile go:lint:new
```

## Full quality gate

Before release preparation or a shared infrastructure merge, run:

```bash
./taskfile go:quality:all
```

The full gate is non-mutating and runs formatting verification, tests, race
tests, full lint, `govulncheck`, and `gosec` across all four modules.

Apply mechanical fixes separately:

```bash
./taskfile go:quality:fix
```

Always review the resulting diff.

## Module selection

All modules run by default. Select one or more modules with:

```bash
GO_QUALITY_MODULE_DIRS="." ./taskfile go:test
GO_QUALITY_MODULE_DIRS="adapters/goadmin" ./taskfile go:lint
GO_QUALITY_MODULE_DIRS="adapters/featuregate examples" ./taskfile go:quality:pr
```

The development workspace pairs each selected nested module with the root, so
adapter checks exercise the current checkout without contaminating root-only
dependency resolution.

For release-graph verification, disable workspace resolution explicitly:

```bash
cd adapters/goadmin
GOWORK=off go test ./...
```

Local `replace` directives must be removed only as part of the documented
root-first publication sequence.

## Lint commands

```bash
./taskfile go:lint
./taskfile go:lint:new
./taskfile go:lint:report
./taskfile go:lint:fix
```

- `go:lint` is the strict full-module check.
- `go:lint:new` blocks findings in files changed from the configured revision.
- `go:lint:report` displays the full backlog without failing.
- `go:lint:fix` applies supported linter fixes.

The current configuration ports the low-noise correctness, HTTP, SQL, JSON,
nil-handling, naming, and standard-library checks from go-admin. Strict blank
assignment/type-assertion `errcheck`, `errorlint`, test `noctx`, and
`testifylint` remain staged until their existing findings are resolved. Do not
hide that work behind broad exclusions.

## Baselines

Baseline commands are available for an intentional staged cleanup:

```bash
./taskfile go:baseline:update:golangci-lint
./taskfile go:baseline:update:gosec
./taskfile go:quality:baseline
```

Updates collect every configured module and write a combined, normalized
baseline under `ops/quality/baselines`. Refresh a baseline only when accepting
or removing known debt; never use it to absorb an unexplained regression.

## GitHub Actions

The Go Quality workflow runs:

- formatting once per change
- tests for all four modules
- blocking change-scoped lint on pull requests and merge queues
- advisory full lint on pull requests
- blocking full lint on `main` and manual runs
- vulnerability and source-security scans for every module
- race tests for code-bearing modules on `main` and manual runs

CI uses Go 1.26.5 because it is the highest minimum declared by the repository's
modules.

## Release validation

Development quality and publishability are separate gates:

1. Run `./taskfile go:quality:all`.
2. Run root and nested-module checks with `GOWORK=off`.
3. Publish the root module first.
4. Remove release-only local root replacements.
5. Repeat nested adapter and example checks from a clean module cache against
   the public root version.

Do not mark release validation complete until the authoritative public tags
exist and the clean-cache checks pass against them.
