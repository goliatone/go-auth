package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type immutableClaimsSnapshot struct {
	subject     string
	issuer      string
	uid         string
	audience    []string
	issuedAt    time.Time
	hasIssuedAt bool
	expiresAt   time.Time
	hasExpires  bool
}

func captureImmutableClaims(claims *JWTClaims) immutableClaimsSnapshot {
	var audienceCopy []string
	if len(claims.RegisteredClaims.Audience) > 0 {
		audienceCopy = append(audienceCopy, claims.RegisteredClaims.Audience...)
	}

	snap := immutableClaimsSnapshot{
		subject:  claims.RegisteredClaims.Subject,
		issuer:   claims.RegisteredClaims.Issuer,
		uid:      claims.UID,
		audience: audienceCopy,
	}

	if claims.RegisteredClaims.IssuedAt != nil {
		snap.issuedAt = claims.RegisteredClaims.IssuedAt.Time
		snap.hasIssuedAt = true
	}

	if claims.RegisteredClaims.ExpiresAt != nil {
		snap.expiresAt = claims.RegisteredClaims.ExpiresAt.Time
		snap.hasExpires = true
	}

	return snap
}

func (snap immutableClaimsSnapshot) validate(claims *JWTClaims) error {
	if claims.RegisteredClaims.Subject != snap.subject {
		return immutableClaimViolation("sub")
	}

	if claims.RegisteredClaims.Issuer != snap.issuer {
		return immutableClaimViolation("iss")
	}

	if claims.UID != snap.uid {
		return immutableClaimViolation("uid")
	}

	if !audienceEqual(claims.RegisteredClaims.Audience, snap.audience) {
		return immutableClaimViolation("aud")
	}

	if err := compareNumericDate(claims.RegisteredClaims.IssuedAt, snap.issuedAt, snap.hasIssuedAt, "iat"); err != nil {
		return err
	}

	if err := compareNumericDate(claims.RegisteredClaims.ExpiresAt, snap.expiresAt, snap.hasExpires, "exp"); err != nil {
		return err
	}

	return nil
}

func compareNumericDate(date *jwt.NumericDate, expected time.Time, expectedSet bool, field string) error {
	if !expectedSet {
		if date != nil {
			return immutableClaimViolation(field)
		}
		return nil
	}

	if date == nil || !date.Time.Equal(expected) {
		return immutableClaimViolation(field)
	}

	return nil
}

func audienceEqual(a jwt.ClaimStrings, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func immutableClaimViolation(field string) error {
	clone := ErrImmutableClaimMutation.Clone()
	if clone == nil {
		return ErrImmutableClaimMutation
	}
	clone.Message = fmt.Sprintf("immutable claim mutated: %s", field)
	clone.Source = ErrImmutableClaimMutation
	return clone.WithMetadata(map[string]any{"claim": field})
}
