package auth0

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-auth"
	goerrors "github.com/goliatone/go-errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenValidator_ValidateValidToken(t *testing.T) {
	privateKey, jwksJSON, kid := newTestJWKS(t)
	server := newJWKSServer(jwksJSON)
	t.Cleanup(server.Close)

	issuer := server.URL + "/"
	audience := "https://api.test"
	namespace := "https://acme.test/"

	validator, err := NewTokenValidator(Config{
		Issuer:   issuer,
		Audience: []string{audience},
		ClaimsMapper: &Auth0ClaimsMapper{
			Namespace: namespace,
		},
	})
	require.NoError(t, err)

	now := time.Now().UTC()
	subject := "auth0|user-123"
	claims := jwt.MapClaims{
		"iss":            issuer,
		"sub":            subject,
		"aud":            []string{audience},
		"iat":            now.Unix(),
		"exp":            now.Add(1 * time.Hour).Unix(),
		"scope":          "read:users write:users",
		"permissions":    []string{"read:users", "write:users"},
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "Test User",
		"nickname":       "tester",
		"picture":        "https://example.com/pic.png",
		"app_metadata": map[string]any{
			"tenant_id":       "tenant-123",
			"organization_id": "org-456",
		},
		namespace + "role": "admin",
		namespace + "resource_roles": map[string]any{
			"project:123": "owner",
		},
	}

	tokenString := signToken(t, privateKey, kid, claims)

	authClaims, err := validator.Validate(tokenString)
	require.NoError(t, err)

	jwtClaims, ok := authClaims.(*auth.JWTClaims)
	require.True(t, ok)

	assert.Equal(t, subject, jwtClaims.UserID())
	assert.Equal(t, "admin", jwtClaims.Role())
	assert.Equal(t, map[string]string{"project:123": "owner"}, jwtClaims.Resources)
	assert.Equal(t, issuer, jwtClaims.Issuer)
	assert.Equal(t, jwt.ClaimStrings{audience}, jwtClaims.Audience)

	metadata := jwtClaims.Metadata
	require.NotNil(t, metadata)
	assert.Equal(t, "user@example.com", metadata["email"])
	assert.Equal(t, true, metadata["email_verified"])
	assert.Equal(t, "Test User", metadata["name"])
	assert.Equal(t, "tester", metadata["nickname"])
	assert.Equal(t, "https://example.com/pic.png", metadata["picture"])
	assert.Equal(t, []string{"read:users", "write:users"}, metadata["permissions"])
	assert.Equal(t, "read:users write:users", metadata["scope"])
	assert.Equal(t, subject, metadata["auth0_sub"])
	assert.Equal(t, "org-456", metadata["organization_id"])
	assert.Equal(t, "tenant-123", metadata["tenant_id"])
}

func TestTokenValidator_ValidateExpiredToken(t *testing.T) {
	privateKey, jwksJSON, kid := newTestJWKS(t)
	server := newJWKSServer(jwksJSON)
	t.Cleanup(server.Close)

	issuer := server.URL + "/"
	audience := "https://api.test"

	validator, err := NewTokenValidator(Config{
		Issuer:   issuer,
		Audience: []string{audience},
	})
	require.NoError(t, err)

	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": "auth0|user-123",
		"aud": []string{audience},
		"iat": now.Add(-2 * time.Hour).Unix(),
		"exp": now.Add(-1 * time.Hour).Unix(),
	}

	tokenString := signToken(t, privateKey, kid, claims)

	_, err = validator.Validate(tokenString)
	require.Error(t, err)
	assert.True(t, auth.IsTokenExpiredError(err))

	var richErr *goerrors.Error
	if assert.ErrorAs(t, err, &richErr) {
		assert.Equal(t, auth.TextCodeTokenExpired, richErr.TextCode)
		assert.Equal(t, "auth0", richErr.Metadata["provider"])
	}
}

func TestTokenValidator_ValidateMalformedToken(t *testing.T) {
	_, jwksJSON, _ := newTestJWKS(t)
	server := newJWKSServer(jwksJSON)
	t.Cleanup(server.Close)

	validator, err := NewTokenValidator(Config{
		Issuer:   server.URL + "/",
		Audience: []string{"https://api.test"},
	})
	require.NoError(t, err)

	_, err = validator.Validate("not.a.valid.token")
	require.Error(t, err)
	assert.True(t, auth.IsMalformedError(err))

	var richErr *goerrors.Error
	if assert.ErrorAs(t, err, &richErr) {
		assert.Equal(t, auth.TextCodeTokenMalformed, richErr.TextCode)
		assert.Equal(t, "auth0", richErr.Metadata["provider"])
	}
}

func TestTokenValidator_ValidateWrongAudience(t *testing.T) {
	privateKey, jwksJSON, kid := newTestJWKS(t)
	server := newJWKSServer(jwksJSON)
	t.Cleanup(server.Close)

	issuer := server.URL + "/"
	audience := "https://api.test"

	validator, err := NewTokenValidator(Config{
		Issuer:   issuer,
		Audience: []string{audience},
	})
	require.NoError(t, err)

	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": "auth0|user-123",
		"aud": []string{"https://wrong.audience"},
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	}

	tokenString := signToken(t, privateKey, kid, claims)

	_, err = validator.Validate(tokenString)
	require.Error(t, err)
	assert.True(t, auth.IsMalformedError(err))

	var richErr *goerrors.Error
	if assert.ErrorAs(t, err, &richErr) {
		assert.Equal(t, auth.TextCodeTokenMalformed, richErr.TextCode)
		assert.Equal(t, "auth0", richErr.Metadata["provider"])
	}
}

func TestTokenValidator_ValidateWrongIssuer(t *testing.T) {
	privateKey, jwksJSON, kid := newTestJWKS(t)
	server := newJWKSServer(jwksJSON)
	t.Cleanup(server.Close)

	issuer := server.URL + "/"
	audience := "https://api.test"

	validator, err := NewTokenValidator(Config{
		Issuer:   issuer,
		Audience: []string{audience},
	})
	require.NoError(t, err)

	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": "https://issuer.invalid/",
		"sub": "auth0|user-123",
		"aud": []string{audience},
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	}

	tokenString := signToken(t, privateKey, kid, claims)

	_, err = validator.Validate(tokenString)
	require.Error(t, err)
	assert.True(t, auth.IsMalformedError(err))

	var richErr *goerrors.Error
	if assert.ErrorAs(t, err, &richErr) {
		assert.Equal(t, auth.TextCodeTokenMalformed, richErr.TextCode)
		assert.Equal(t, "auth0", richErr.Metadata["provider"])
	}
}

func newTestJWKS(t *testing.T) (*rsa.PrivateKey, []byte, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-key"
	jwk := map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
	}

	jwks := map[string]any{
		"keys": []map[string]any{jwk},
	}

	data, err := json.Marshal(jwks)
	require.NoError(t, err)

	return privateKey, data, kid
}

func newJWKSServer(jwks []byte) *httptest.Server {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			payload := map[string]any{
				"jwks_uri": server.URL + "/.well-known/jwks.json",
			}
			_ = json.NewEncoder(w).Encode(payload)
		case "/.well-known/jwks.json", "/":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(jwks)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return server
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.Claims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(key)
	require.NoError(t, err)

	return signed
}
