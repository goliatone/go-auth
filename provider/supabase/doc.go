// Package supabase integrates Supabase Auth with go-auth's hardened OIDC and
// provider-session boundaries.
//
// The package intentionally exposes narrow configuration, lifecycle, factor,
// session, and OAuth authorization-decision services. It does not expose an
// arbitrary privileged HTTP client, render login/consent UI, own business
// authorization, or make service-role credentials available to browsers.
//
// Provider API behavior is bounded by Config API-version fields and fake
// provider contract tests. Deployments must still run the live conformance
// suite before enabling a provider version, public-signup policy, or
// cross-project user-token trust branch.
package supabase
