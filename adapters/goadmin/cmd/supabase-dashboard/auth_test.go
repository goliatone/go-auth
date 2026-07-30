package main

import (
	"context"
	"strings"
	"testing"

	auth "github.com/goliatone/go-auth"
	"github.com/google/uuid"
)

type noPasswordIdentityProvider struct{}

func (noPasswordIdentityProvider) VerifyIdentity(context.Context, string, string) (auth.Identity, error) {
	return nil, auth.ErrIdentityNotFound
}

func (noPasswordIdentityProvider) FindIdentityByIdentifier(context.Context, string) (auth.Identity, error) {
	return nil, auth.ErrIdentityNotFound
}

func TestPrincipalTokenIssuerProducesValidatedSessionClaims(t *testing.T) {
	cfg := localAuthConfig{signingKey: auth.NewSecret(strings.Repeat("k", 32))}
	auther := auth.NewAuthenticator(noPasswordIdentityProvider{}, cfg)
	issuer, err := principalTokenIssuer(auther.TokenService(), cfg)
	if err != nil {
		t.Fatalf("principalTokenIssuer: %v", err)
	}
	identity := auth.NewIdentityFromUser(&auth.User{
		ID:       uuid.New(),
		Username: "supabase-user",
		Email:    "user@example.com",
		Role:     auth.RoleOwner,
		Status:   auth.UserStatusActive,
	})
	token, err := issuer.GeneratePrincipal(identity, map[string]any{
		"provider":        "supabase",
		"assurance_level": "aal1",
	})
	if err != nil {
		t.Fatalf("GeneratePrincipal: %v", err)
	}
	claims, err := auther.TokenService().Validate(token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject() != identity.ID() || claims.Role() != string(auth.RoleOwner) {
		t.Fatalf("claims subject/role = %q/%q", claims.Subject(), claims.Role())
	}
	sessionClaims, ok := claims.(*auth.JWTClaims)
	if !ok {
		t.Fatalf("claims type = %T", claims)
	}
	if sessionClaims.TokenUse() != auth.TokenTypeSession {
		t.Fatalf("token use = %q", sessionClaims.TokenUse())
	}
	if sessionClaims.Metadata["provider"] != "supabase" || sessionClaims.Metadata["assurance_level"] != "aal1" {
		t.Fatalf("metadata = %#v", sessionClaims.Metadata)
	}
}
