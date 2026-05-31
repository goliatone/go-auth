// Package preset contains thin provider conventions for generic OIDC.
//
// Presets should only fill configuration such as issuer conventions, scopes,
// display metadata, and claim-key defaults. Providers that need management
// APIs, sync workflows, custom validation, or non-OIDC protocol behavior should
// remain top-level provider packages instead.
package preset
