# Provider Package Policy

Provider packages should stay small and use the generic OIDC implementation
when the provider does not need custom behavior.

## OIDC Presets

Use `provider/oidc/preset` for providers that only need OIDC configuration:

- issuer or tenant URL conventions;
- default scopes;
- claim-key mappings;
- display labels or icon keys;
- mapper defaults.

Examples include Okta, Azure AD, Google Workspace, and Auth0 browser SSO when
they are used as standard OIDC providers.

Presets may choose issuer, scopes, claim keys, and display defaults. They must
not weaken explicit token-endpoint authentication, callback-mode, signing
algorithm, or response-limit validation. Provider sessions remain
provider-neutral and server-side.

## Top-Level Provider Packages

Create a top-level provider package only when the provider needs behavior
beyond OIDC configuration:

- management APIs;
- user sync workflows;
- custom token validation;
- non-OIDC protocol behavior;
- provider-specific operational code.

`provider/auth0` remains a top-level package because it already provides Auth0
JWT validation, claims mapping, management API integration, and sync support.

## Adding A Provider

Before adding a new provider package, decide whether it is a thin OIDC preset
or a provider-specific implementation. Prefer `provider/oidc/preset` unless the
provider needs custom code that cannot be expressed as OIDC configuration.
