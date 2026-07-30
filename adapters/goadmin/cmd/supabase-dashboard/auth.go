package main

import (
	"fmt"
	"maps"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
)

type sessionClaimsSigner interface {
	SignClaimsWithType(*auth.JWTClaims, string) (string, error)
}

func principalTokenIssuer(tokenService auth.TokenService, cfg localAuthConfig) (oidc.PrincipalTokenIssuer, error) {
	signer, ok := tokenService.(sessionClaimsSigner)
	if !ok {
		return nil, fmt.Errorf("local token service does not support typed session claims")
	}
	return oidc.PrincipalTokenIssuerFunc(func(identity auth.Identity, normalizedClaims map[string]any) (string, error) {
		if identity == nil {
			return "", fmt.Errorf("local identity is required")
		}
		now := time.Now().UTC()
		metadata := map[string]any{}
		maps.Copy(metadata, normalizedClaims)
		return signer.SignClaimsWithType(&auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.GetIssuer(),
				Subject:   identity.ID(),
				Audience:  cfg.GetAudience(),
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(cfg.tokenDuration())),
			},
			UID:      identity.ID(),
			UserRole: identity.Role(),
			Metadata: metadata,
		}, auth.TokenTypeSession)
	}), nil
}
