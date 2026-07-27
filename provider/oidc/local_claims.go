package oidc

import (
	"fmt"

	auth "github.com/goliatone/go-auth"
)

// PrincipalLocalClaims returns only the normalized claims explicitly named by
// policy. Application subject remains the local JWT subject and is not copied.
func PrincipalLocalClaims(principal auth.AuthenticatedPrincipal, policy LocalClaimPolicy) (map[string]any, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	claims := make(map[string]any, len(policy.Allow))
	for _, claim := range policy.Allow {
		switch claim {
		case LocalClaimProvider:
			claims[string(claim)] = principal.Provider()
		case LocalClaimProviderSubject:
			claims[string(claim)] = principal.ProviderSubject()
		case LocalClaimProviderSessionID:
			claims[string(claim)] = principal.ProviderSessionID()
		case LocalClaimClientID:
			claims[string(claim)] = principal.ClientID()
		case LocalClaimAssuranceLevel:
			claims[string(claim)] = principal.AssuranceLevel()
		case LocalClaimAssuranceMethods:
			claims[string(claim)] = principal.AssuranceMethods()
		case LocalClaimAuthenticationTime:
			if !principal.AuthenticationAt().IsZero() {
				claims[string(claim)] = principal.AuthenticationAt().Unix()
			}
		case LocalClaimTenantID:
			claims[string(claim)] = principal.TenantID()
		case LocalClaimOrganizationID:
			claims[string(claim)] = principal.OrganizationID()
		case LocalClaimPermissionVersion:
			claims[string(claim)] = principal.PermissionVersion()
		default:
			return nil, fmt.Errorf("oidc: unsupported local claim %q", claim)
		}
	}
	return claims, nil
}
