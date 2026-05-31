# go-admin Adapter

This nested module wires go-auth SSO into go-admin without adding a go-admin
dependency to the root `go-auth` module.

The module boundary is intentional:

- root `go-auth` does not import `github.com/goliatone/go-admin`;
- this adapter may import both `go-auth` and `go-admin`;
- browser SSO routes live on the admin UI surface;
- public provider-list, begin-login, and callback routes bypass admin auth;
- protected link and logout routes use the admin auth middleware.

Local development can use a temporary workspace or `replace` directives, but
released module files should not require sibling checkout paths.

## Quickstart

Use `SetupSSO` before `adm.Initialize(...)`.

Minimum inputs:

- `Admin`: the go-admin instance.
- `AuthConfig`: the go-auth config used for local JWT cookies.
- `Auther` or `IdentityProvider`: existing go-auth authenticator or provider.
- `Browser`: OIDC browser authenticator.
- `ProviderEntries` or `ProviderConfigs` plus `ProviderLoginURL`.
- `ManualLinkVerifier` when `ManualLinker` is configured.
- `ManualUnlinker` when protected account unlinking should be enabled.

`SetupSSO` creates or reuses `RouteAuthenticator`, registers
`admin.GoAuthAuthenticator`, registers `admin.GoAuthAuthorizer`, registers the
SSO module, and optionally adds `quickstart.WithAuthUIViewContextBuilder` to
auth UI route registration.

## Troubleshooting

No SSO controls on login:
Confirm `sso_providers` is present in auth UI view context. Zero providers is
intentional and should render no SSO divider or provider section.

Provider link is missing or unsafe:
Provider entries must use same-origin relative login URLs. Provider configs
need a `ProviderLoginURL` builder so the template receives real begin-login
URLs instead of placeholders.

Callback succeeds but admin remains logged out:
Confirm handlers use `RouteAuthenticator.SetAuthCookie` and the same go-auth
`AuthConfig` as local login. Cookie name, path, SameSite, Secure, and duration
come from that route authenticator.

Provider-list endpoint leaks too much:
Return only key, label, login URL, icon metadata, and disabled reason. Client
secrets, tokens, discovery documents, and raw provider config must stay server
side.

Manual account link returns not configured or forbidden:
Manual linking is fail-closed. If a host configures `ManualLinker`, it must also
configure `ManualLinkVerifier`. The verifier must prove that the authenticated
admin user may link the requested provider subject, for example by completing a
provider callback or checking a host-owned proof record. The adapter rejects the
link before calling `ManualLinker` when proof is missing, mismatched, or denied.

Manual account unlink returns not configured:
Configure `ManualUnlinker` to remove a verified provider-subject mapping for the
authenticated admin user. Hosts can implement it with the provider-neutral
`auth.IdentifierStore.Delete` contract.

Custom admin permission denied:
Map IdP permission, role, or group claims with `NewClaimPermissionResolver`,
then compose with host-local policy using `ComposePermissionResolvers`.
Resolver failures intentionally deny custom actions.
