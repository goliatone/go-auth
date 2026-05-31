package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
)

func TestDiscoverRejectsIssuerMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DiscoveryMetadata{
			Issuer:  "https://other.example/",
			JWKSURI: "https://issuer.example/jwks",
		})
	}))
	defer server.Close()

	_, err := Discover(context.Background(), ProviderConfig{
		Key:         "test",
		Issuer:      server.URL,
		ClientID:    "client",
		RedirectURL: "https://app.example/callback",
	}, server.Client())
	if err == nil || !strings.Contains(err.Error(), "oidc discovery failed") {
		t.Fatalf("expected discovery issuer mismatch error, got %v", err)
	}
}

func TestTokenValidatorValidate(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	key := mustRSAKey(t)
	issuer := "https://issuer.example/"
	validator := newTestValidator(t, issuer, []jwk{rsaJWK("kid-1", key.PublicKey, "RS256", "sig", nil)}, now)

	token := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": issuer,
		"sub": "user-1",
		"aud": "api://default",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
	})

	claims, err := validator.Validate(token)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if claims.Subject() != "user-1" {
		t.Fatalf("subject = %q, want user-1", claims.Subject())
	}
}

func TestTokenValidatorValidateIDTokenDefaultsAudienceToClientID(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	key := mustRSAKey(t)
	issuer := "https://issuer.example/"
	validator := newTestValidator(t, issuer, []jwk{rsaJWK("kid-1", key.PublicKey, "RS256", "sig", nil)}, now)

	valid := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": issuer,
		"sub": "user-1",
		"aud": "client",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
	})
	if _, err := validator.ValidateIDToken(context.Background(), valid, ""); err != nil {
		t.Fatalf("ValidateIDToken returned error for client audience: %v", err)
	}

	wrongAudience := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": issuer,
		"sub": "user-1",
		"aud": "api://default",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
	})
	if _, err := validator.ValidateIDToken(context.Background(), wrongAudience, ""); !isInvalidOIDCToken(err) {
		t.Fatalf("expected ID-token audience failure, got %v", err)
	}
}

func TestTokenValidatorValidateIDTokenRequiresIssuedAt(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	key := mustRSAKey(t)
	issuer := "https://issuer.example/"
	validator := newTestValidator(t, issuer, []jwk{rsaJWK("kid-1", key.PublicKey, "RS256", "sig", nil)}, now)

	missingIssuedAt := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": issuer,
		"sub": "user-1",
		"aud": "client",
		"exp": now.Add(time.Hour).Unix(),
	})
	if _, err := validator.ValidateIDToken(context.Background(), missingIssuedAt, ""); !isInvalidOIDCToken(err) {
		t.Fatalf("expected missing iat to fail ID-token validation, got %v", err)
	}
}

func TestTokenValidatorRejectsMalformedWithFallbackError(t *testing.T) {
	validator := newTestValidator(t, "https://issuer.example/", nil, time.Now())
	_, err := validator.Validate("not-a-jwt")
	if !auth.IsMalformedError(err) {
		t.Fatalf("expected malformed error, got %v", err)
	}
}

func TestTokenValidatorTerminalFailures(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	key := mustRSAKey(t)
	issuer := "https://issuer.example/"
	validator := newTestValidator(t, issuer, []jwk{rsaJWK("kid-1", key.PublicKey, "RS256", "sig", nil)}, now)

	tests := []struct {
		name  string
		token string
		check func(error) bool
	}{
		{
			name: "expired",
			token: signToken(t, key, "kid-1", jwt.MapClaims{
				"iss": issuer, "sub": "user-1", "aud": "api://default",
				"exp": now.Add(-time.Minute).Unix(), "iat": now.Add(-time.Hour).Unix(),
			}),
			check: auth.IsTokenExpiredError,
		},
		{
			name: "wrong issuer",
			token: signToken(t, key, "kid-1", jwt.MapClaims{
				"iss": "https://wrong.example/", "sub": "user-1", "aud": "api://default",
				"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
			}),
			check: isInvalidOIDCToken,
		},
		{
			name: "wrong audience",
			token: signToken(t, key, "kid-1", jwt.MapClaims{
				"iss": issuer, "sub": "user-1", "aud": "api://other",
				"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
			}),
			check: isInvalidOIDCToken,
		},
		{
			name: "unknown key",
			token: signToken(t, key, "missing", jwt.MapClaims{
				"iss": issuer, "sub": "user-1", "aud": "api://default",
				"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
			}),
			check: isInvalidOIDCToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validator.Validate(tt.token)
			if err == nil || !tt.check(err) || auth.IsMalformedError(err) {
				t.Fatalf("expected terminal validation error, got %v", err)
			}
		})
	}
}

func TestTokenValidatorRejectsAlgorithmsAndKeyUse(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	key := mustRSAKey(t)
	issuer := "https://issuer.example/"

	t.Run("none algorithm", func(t *testing.T) {
		validator := newTestValidator(t, issuer, []jwk{rsaJWK("kid-1", key.PublicKey, "RS256", "sig", nil)}, now)
		token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
			"iss": issuer, "sub": "user-1", "aud": "api://default",
			"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
		})
		token.Header["kid"] = "kid-1"
		raw, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatal(err)
		}
		_, err = validator.Validate(raw)
		if !isInvalidOIDCToken(err) {
			t.Fatalf("expected invalid token error, got %v", err)
		}
	})

	t.Run("unexpected algorithm", func(t *testing.T) {
		validator := newTestValidator(t, issuer, []jwk{rsaJWK("kid-1", key.PublicKey, "RS256", "sig", nil)}, now)
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": issuer, "sub": "user-1", "aud": "api://default",
			"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
		})
		token.Header["kid"] = "kid-1"
		raw, err := token.SignedString([]byte("secret"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = validator.Validate(raw)
		if !isInvalidOIDCToken(err) {
			t.Fatalf("expected invalid token error, got %v", err)
		}
	})

	t.Run("jwk use not signing", func(t *testing.T) {
		validator := newTestValidator(t, issuer, []jwk{rsaJWK("kid-1", key.PublicKey, "RS256", "enc", nil)}, now)
		token := signToken(t, key, "kid-1", jwt.MapClaims{
			"iss": issuer, "sub": "user-1", "aud": "api://default",
			"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
		})
		_, err := validator.Validate(token)
		if !isInvalidOIDCToken(err) {
			t.Fatalf("expected invalid token error, got %v", err)
		}
	})

	t.Run("jwk key ops without verify", func(t *testing.T) {
		validator := newTestValidator(t, issuer, []jwk{rsaJWK("kid-1", key.PublicKey, "RS256", "", []string{"encrypt"})}, now)
		token := signToken(t, key, "kid-1", jwt.MapClaims{
			"iss": issuer, "sub": "user-1", "aud": "api://default",
			"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
		})
		_, err := validator.Validate(token)
		if !isInvalidOIDCToken(err) {
			t.Fatalf("expected invalid token error, got %v", err)
		}
	})
}

func TestTokenValidatorRejectsUnsupportedConfiguredAlgorithmAtSetup(t *testing.T) {
	key := mustRSAKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: []jwk{rsaJWK("kid-1", key.PublicKey, "RS256", "sig", nil)}})
	}))
	defer server.Close()

	provider := testProviderConfig("https://issuer.example/")
	provider.AllowedAlgorithms = []string{"ES256"}
	_, err := NewTokenValidator(context.Background(), provider, DiscoveryMetadata{
		Issuer:     "https://issuer.example/",
		JWKSURI:    server.URL,
		Algorithms: []string{"ES256"},
	}, WithValidatorHTTPClient(server.Client()))
	if err == nil || !strings.Contains(err.Error(), "configuration") {
		t.Fatalf("expected unsupported configured algorithm setup error, got %v", err)
	}
}

func TestTokenValidatorRejectsDiscoveryWithNoSupportedAlgorithmsAtSetup(t *testing.T) {
	key := mustRSAKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: []jwk{rsaJWK("kid-1", key.PublicKey, "RS256", "sig", nil)}})
	}))
	defer server.Close()

	provider := testProviderConfig("https://issuer.example/")
	provider.AllowedAlgorithms = nil
	_, err := NewTokenValidator(context.Background(), provider, DiscoveryMetadata{
		Issuer:     "https://issuer.example/",
		JWKSURI:    server.URL,
		Algorithms: []string{"ES256"},
	}, WithValidatorHTTPClient(server.Client()))
	if err == nil || !strings.Contains(err.Error(), "configuration") {
		t.Fatalf("expected unsupported discovery algorithm setup error, got %v", err)
	}
}

func TestTokenValidatorRefreshesJWKSForRotation(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	key1 := mustRSAKey(t)
	key2 := mustRSAKey(t)
	var calls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		keys := []jwk{rsaJWK("kid-1", key1.PublicKey, "RS256", "sig", nil)}
		if atomic.LoadInt32(&calls) > 1 {
			keys = append(keys, rsaJWK("kid-2", key2.PublicKey, "RS256", "sig", nil))
		}
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: keys})
	}))
	defer server.Close()

	validator, err := NewTokenValidator(context.Background(), testProviderConfig("https://issuer.example/"), DiscoveryMetadata{
		Issuer:     "https://issuer.example/",
		JWKSURI:    server.URL,
		Algorithms: []string{"RS256"},
	}, WithValidatorHTTPClient(server.Client()), WithValidatorClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}

	token := signToken(t, key2, "kid-2", jwt.MapClaims{
		"iss": "https://issuer.example/", "sub": "user-1", "aud": "api://default",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
	})
	if _, err := validator.Validate(token); err != nil {
		t.Fatalf("expected validation after refresh, got %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected JWKS refresh for unknown kid, got %d fetches", calls)
	}
}

func newTestValidator(t *testing.T, issuer string, keys []jwk, now time.Time) *TokenValidator {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: keys})
	}))
	t.Cleanup(server.Close)

	validator, err := NewTokenValidator(context.Background(), testProviderConfig(issuer), DiscoveryMetadata{
		Issuer:     issuer,
		JWKSURI:    server.URL,
		Algorithms: []string{"RS256"},
	}, WithValidatorHTTPClient(server.Client()), WithValidatorClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func testProviderConfig(issuer string) ProviderConfig {
	return ProviderConfig{
		Key:               "test",
		Issuer:            issuer,
		ClientID:          "client",
		RedirectURL:       "https://app.example/callback",
		Audience:          []string{"api://default"},
		AllowedAlgorithms: []string{"RS256"},
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rsaJWK(kid string, key rsa.PublicKey, alg string, use string, keyOps []string) jwk {
	return jwk{
		KeyID:     kid,
		KeyType:   "RSA",
		Algorithm: alg,
		Use:       use,
		KeyOps:    keyOps,
		Modulus:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		Exponent:  base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func isInvalidOIDCToken(err error) bool {
	if err == nil {
		return false
	}
	if auth.IsMalformedError(err) {
		return false
	}
	var rich interface{ TextCodeValue() string }
	if errors.As(err, &rich) {
		return rich.TextCodeValue() == TextCodeOIDCInvalidIDToken
	}
	return strings.Contains(err.Error(), "oidc id token is invalid")
}
