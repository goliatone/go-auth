# go-admin Adapter

This nested module will host the go-admin SSO adapter for `go-auth`.

The module boundary is intentional:

- root `go-auth` does not import `github.com/goliatone/go-admin`;
- this adapter may import both `go-auth` and `go-admin`;
- route contracts, quickstart helpers, and SSO handlers are implemented in the
  follow-up SSO tasks.

Local development can use a temporary workspace or `replace` directives, but
released module files should not require sibling checkout paths.
