package jwtware_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/mock"

	"github.com/goliatone/go-auth/middleware/jwtware"
)

// By default we set an expiration time 1 hour from now
func generateToken(t *testing.T, method jwt.SigningMethod, key []byte, claims jwt.MapClaims) string {
	t.Helper()

	if claims["exp"] == nil {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}

	token := jwt.NewWithClaims(method, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

//--------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------

func TestJWTWare_BasicHeaderExtraction(t *testing.T) {
	signingKey := []byte("test-secret")
	jwtAlg := jwt.SigningMethodHS256.Alg()

	validToken := generateToken(t, jwt.SigningMethodHS256, signingKey, jwt.MapClaims{
		"sub": "12345",
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    signingKey,
			JWTAlg: jwtAlg,
		},
		SuccessHandler: func(ctx router.Context) error {
			return ctx.Next()
		},
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
		// it will look for Authorization: Bearer <token>
	}

	middleware := jwtware.New(cfg)

	// Test with valid token
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer " + validToken
	// Set up expectation for GetString call
	ctx.On("GetString", "Authorization", "").Return("Bearer " + validToken)
	// Set up expectation for Locals call (setting the token)
	ctx.On("Locals", "user", mock.AnythingOfType("*jwt.Token")).Return(nil)

	err := middleware(ctx)
	if err != nil {
		t.Fatalf("unexpected error for valid token: %v", err)
	}
	if !ctx.NextCalled {
		t.Errorf("expected NextCalled to be true, but got false")
	}

	// Test with missing token
	ctx = router.NewMockContext()
	// Set up expectation for GetString call returning empty string
	ctx.On("GetString", "Authorization", "").Return("")
	err = middleware(ctx)
	if err == nil {
		t.Fatal("expected error for missing token, got nil")
	}
	if !strings.Contains(err.Error(), jwtware.ErrJWTMissingOrMalformed.Error()) {
		t.Errorf("expected missing token error, got: %v", err)
	}

	// Test with malformed token
	ctx = router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer malformed.token.structure"
	ctx.On("GetString", "Authorization", "").Return("Bearer malformed.token.structure")
	err = middleware(ctx)
	if err == nil {
		t.Fatal("expected error for malformed token, got nil")
	}
	if !strings.Contains(err.Error(), "token is malformed") {
		t.Errorf("expected 'token is malformed' error, got: %v", err)
	}
}

func TestJWTWare_ExpiredToken(t *testing.T) {
	signingKey := []byte("test-secret")
	jwtAlg := jwt.SigningMethodHS256.Alg()

	claims := jwt.MapClaims{
		"sub": "12345",
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	}
	expiredToken := generateToken(t, jwt.SigningMethodHS256, signingKey, claims)

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    signingKey,
			JWTAlg: jwtAlg,
		},
		ErrorHandler: func(c router.Context, err error) error {
			return err
		},
	}
	middleware := jwtware.New(cfg)

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer " + expiredToken
	ctx.On("GetString", "Authorization", "").Return("Bearer " + expiredToken)

	err := middleware(ctx)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
	if !strings.Contains(err.Error(), "token is expired") {
		t.Errorf("expected token expired error, got: %v", err)
	}
}

func TestJWTWare_CustomTokenLookup(t *testing.T) {
	signingKey := []byte("test-secret")
	jwtAlg := jwt.SigningMethodHS256.Alg()

	validToken := generateToken(t, jwt.SigningMethodHS256, signingKey, jwt.MapClaims{
		"sub": "12345",
	})

	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    signingKey,
			JWTAlg: jwtAlg,
		},
		TokenLookup: "query:token,param:jwt,cookie:jwt_cookie",
	}
	middleware := jwtware.New(cfg)

	// Test query parameter
	ctx := router.NewMockContext()
	ctx.QueriesM["token"] = validToken
	// If the middleware uses GetString for query params, set up the expectation
	ctx.On("GetString", "token", "").Return(validToken).Maybe()
	ctx.On("Locals", "user", mock.AnythingOfType("*jwt.Token")).Return(nil)

	err := middleware(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !ctx.NextCalled {
		t.Errorf("expected Next to be invoked for valid token")
	}

	// Test URL parameter
	ctx = router.NewMockContext()
	ctx.ParamsM["jwt"] = validToken
	// If the middleware uses GetString for params, set up the expectation
	ctx.On("GetString", "jwt", "").Return(validToken).Maybe()
	ctx.On("Locals", "user", mock.AnythingOfType("*jwt.Token")).Return(nil)
	err = middleware(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Test cookie
	ctx = router.NewMockContext()
	ctx.CookiesM["jwt_cookie"] = validToken
	// If the middleware uses GetString for cookies, set up the expectation
	ctx.On("GetString", "jwt_cookie", "").Return(validToken).Maybe()
	ctx.On("Locals", "user", mock.AnythingOfType("*jwt.Token")).Return(nil)
	err = middleware(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// customPathMock overrides Path() from our base MockContext.
type customPathMock struct {
	*router.MockContext
	pathOverride string
}

func (m *customPathMock) Path() string {
	return m.pathOverride
}

func TestJWTWare_FilterFunction(t *testing.T) {
	signingKey := []byte("test-secret")
	cfg := jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    signingKey,
			JWTAlg: jwt.SigningMethodHS256.Alg(),
		},
		Filter: func(ctx router.Context) bool {
			// skip the middleware on "/public"
			return ctx.Path() == "/public"
		},
	}
	middleware := jwtware.New(cfg)

	// context's Path() returns "/public".
	ctx := &customPathMock{
		MockContext:  router.NewMockContext(),
		pathOverride: "/public",
	}

	// because Filter returns true for Path() == "/public",
	// the middleware should skip token checking and call ctx.Next()
	err := middleware(ctx)
	if err != nil {
		t.Fatalf("expected no error because Filter should skip, got %v", err)
	}
	if !ctx.NextCalled {
		t.Errorf("expected Next() to be invoked due to Filter skip")
	}
}

func TestJWTWare_CustomClaims(t *testing.T) {
	signingKey := []byte("test-secret")

	type MyCustomClaims struct {
		UserID string `json:"user_id"`
		jwt.RegisteredClaims
	}

	cfg := jwtware.GetDefaultConfig(jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    signingKey,
			JWTAlg: jwt.SigningMethodHS256.Alg(),
		},
		Claims: &MyCustomClaims{},
	})

	middleware := jwtware.New(cfg)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &MyCustomClaims{
		UserID: "u-12345",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	signed, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatalf("failed to sign custom token: %v", err)
	}

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer " + signed
	ctx.On("GetString", "Authorization", "").Return("Bearer " + signed)
	ctx.On("Locals", cfg.ContextKey, mock.AnythingOfType("*jwt.Token")).Return(nil)

	err = middleware(ctx)
	if err != nil {
		t.Fatalf("expected no error for valid custom claims token, got %v", err)
	}

	val := ctx.Locals(cfg.ContextKey)
	if val == nil {
		t.Fatal("expected token to be stored in ctx locals, got nil: -> " + cfg.ContextKey)
	}

	tokenVal, ok := val.(*jwt.Token)
	if !ok {
		t.Fatalf("expected *jwt.Token, got %T", val)
	}
	custom, ok := tokenVal.Claims.(*MyCustomClaims)
	if !ok {
		t.Fatalf("expected *MyCustomClaims, got %T", tokenVal.Claims)
	}
	if custom.UserID != "u-12345" {
		t.Errorf("expected user_id = 'u-12345', got %s", custom.UserID)
	}
}

func TestJWTWare_MultipleSigningKeys(t *testing.T) {
	key1 := []byte("secret1")
	key2 := []byte("secret2")

	cfg := jwtware.Config{
		SigningKeys: map[string]jwtware.SigningKey{
			"key-1": {
				Key:    key1,
				JWTAlg: jwt.SigningMethodHS256.Alg(),
			},
			"key-2": {
				Key:    key2,
				JWTAlg: jwt.SigningMethodHS256.Alg(),
			},
		},
	}
	middleware := jwtware.New(cfg)

	// Generate token signed with key1
	token := jwt.New(jwt.SigningMethodHS256)
	token.Header["kid"] = "key-1" // Key ID
	token.Claims = jwt.MapClaims{"sub": "testing"}
	signed, err := token.SignedString(key1)
	if err != nil {
		t.Fatalf("could not sign with key1: %v", err)
	}

	// Validate
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer " + signed
	ctx.On("GetString", "Authorization", "").Return("Bearer " + signed)
	ctx.On("Locals", "user", mock.AnythingOfType("*jwt.Token")).Return(nil)
	err = middleware(ctx)
	if err != nil {
		t.Fatalf("expected no error when kid=key-1 is used, got %v", err)
	}
}

func TestJWTWare_JWKSetURL(t *testing.T) {
	// Spin up a local HTTP test server that returns a static JWK Set.
	// We generate an HS256 JWK for a demo. In real usage, you'd have RSA or EC JWKs.
	jwksJSON := `{
      "keys": [
        {
          "kty": "oct",
          "kid": "local-jwk",
          "k":   "c2VjcmV0LWtleS1ieXRlcw",
          "alg": "HS256"
        }
      ]
    }`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer ts.Close()

	// The actual secret in that JWK is "secret-key-bytes" base64 decoded
	signingKey := []byte("secret-key-bytes")

	// Generate token with kid = "local-jwk"
	token := jwt.New(jwt.SigningMethodHS256)
	token.Header["kid"] = "local-jwk"
	token.Claims = jwt.MapClaims{"sub": "12345"}
	signed, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// Create config that uses the JWK set URL
	cfg := jwtware.Config{
		JWKSetURLs: []string{ts.URL},
		// We must specify the correct alg if we have it, or leave the JWK to handle it
		// We do not set SigningKey or SigningKeys because we want the JWK to be used
	}
	middleware := jwtware.New(cfg)

	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer " + signed
	ctx.On("GetString", "Authorization", "").Return("Bearer " + signed)
	ctx.On("Locals", "user", mock.AnythingOfType("*jwt.Token")).Return(nil)

	err = middleware(ctx)
	if err != nil {
		t.Fatalf("expected no error for valid JWK-signed token, got: %v", err)
	}
	if !ctx.NextCalled {
		t.Error("expected NextCalled to be true")
	}
}

func TestJWTWare_CustomKeyfunc(t *testing.T) {
	cfg := jwtware.Config{
		KeyFunc: func(token *jwt.Token) (any, error) {
			return nil, errors.New("forced error from custom KeyFunc")
		},
		ErrorHandler: func(c router.Context, err error) error {
			return err
		},
	}
	middleware := jwtware.New(cfg)

	validToken := generateToken(t, jwt.SigningMethodHS256, []byte("any"), jwt.MapClaims{"sub": "abc"})
	ctx := router.NewMockContext()
	ctx.HeadersM["Authorization"] = "Bearer " + validToken
	ctx.On("GetString", "Authorization", "").Return("Bearer " + validToken)
	err := middleware(ctx)
	if err == nil {
		t.Fatal("expected forced error from custom KeyFunc, got nil")
	}

	if !strings.Contains(err.Error(), "forced error") {
		t.Errorf("expected KeyFunc forced error message, got: %v", err)
	}
}

func TestJWTWare_Extractors(t *testing.T) {
	signingKey := []byte("test-secret")

	// Generate a valid token using your helper.
	validToken := generateToken(t, jwt.SigningMethodHS256, signingKey, jwt.MapClaims{
		"sub": "12345",
	})

	cfg := jwtware.GetDefaultConfig(jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key:    signingKey,
			JWTAlg: jwt.SigningMethodHS256.Alg(),
		},
		ErrorHandler: func(c router.Context, err error) error {
			fmt.Printf("ERROR in middleware: %v\n", err)
			return err
		},
		SuccessHandler: func(ctx router.Context) error {
			fmt.Println("SUCCESS: calling Next()")
			return ctx.Next()
		},
		// This instructs the middleware to look in multiple places, in order:
		// 1. Authorization header
		// 2. Query param "jwt"
		// 3. URL param "token"
		// 4. Cookie named "jwt_cookie"
		TokenLookup: "header:Authorization,query:jwt,param:token,cookie:jwt_cookie",
	})

	middleware := jwtware.New(cfg)

	tests := []struct {
		name      string
		setToken  func(*router.MockContext)
		wantError bool
	}{
		{
			name: "token in header -> success",
			setToken: func(ctx *router.MockContext) {
				ctx.HeadersM["Authorization"] = "Bearer " + validToken
				ctx.On("GetString", "Authorization", "").Return("Bearer " + validToken).Maybe()
				ctx.On("Locals", cfg.ContextKey, mock.AnythingOfType("*jwt.Token")).Return(nil).Maybe()
			},
		},
		{
			name: "token in query -> success",
			setToken: func(ctx *router.MockContext) {
				ctx.QueriesM["jwt"] = validToken
				ctx.On("GetString", "Authorization", "").Return("").Maybe()
				ctx.On("GetString", "jwt", "").Return(validToken).Maybe()
				ctx.On("Locals", cfg.ContextKey, mock.AnythingOfType("*jwt.Token")).Return(nil).Maybe()
			},
		},
		{
			name: "token in param -> success",
			setToken: func(ctx *router.MockContext) {
				ctx.ParamsM["token"] = validToken
				ctx.On("GetString", "Authorization", "").Return("").Maybe()
				ctx.On("GetString", "jwt", "").Return("").Maybe()
				ctx.On("GetString", "token", "").Return(validToken).Maybe()
				ctx.On("Locals", cfg.ContextKey, mock.AnythingOfType("*jwt.Token")).Return(nil).Maybe()
			},
		},
		{
			name: "token in cookie -> success",
			setToken: func(ctx *router.MockContext) {
				ctx.CookiesM["jwt_cookie"] = validToken
				ctx.On("GetString", "Authorization", "").Return("").Maybe()
				ctx.On("GetString", "jwt", "").Return("").Maybe()
				ctx.On("GetString", "token", "").Return("").Maybe()
				ctx.On("GetString", "jwt_cookie", "").Return(validToken).Maybe()
				ctx.On("Locals", cfg.ContextKey, mock.AnythingOfType("*jwt.Token")).Return(nil).Maybe()
			},
		},
		{
			name: "no token anywhere -> error",
			setToken: func(ctx *router.MockContext) {
				ctx.On("GetString", "Authorization", "").Return("").Maybe()
				ctx.On("GetString", "jwt", "").Return("").Maybe()
				ctx.On("GetString", "token", "").Return("").Maybe()
				ctx.On("GetString", "jwt_cookie", "").Return("").Maybe()
			},
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := router.NewMockContext()
			tc.setToken(ctx)

			err := middleware(ctx)
			if tc.wantError {
				if err == nil {
					t.Errorf("expected an error, but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if !ctx.NextCalled {
				t.Errorf("middleware did not call Next() on success")
			}
		})
	}
}
