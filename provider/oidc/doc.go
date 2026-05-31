// Package oidc implements generic OpenID Connect support for go-auth.
//
// The package owns issuer discovery, JWKS validation, authorization-code
// browser SSO orchestration, claim mapping, and provider-neutral identity
// linking. It deliberately does not depend on go-admin and does not write HTTP
// cookies directly; browser callbacks return a BrowserSessionResult that host
// handlers can use with auth.RouteAuthenticator.SetAuthCookie.
package oidc
