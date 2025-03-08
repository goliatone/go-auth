package jwtware_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-router"

	"github.com/goliatone/go-auth/middleware/jwtware"
)

type mockContext struct {
	headers      map[string]string
	cookies      map[string]string
	params       map[string]string
	queries      map[string]string
	locals       map[any]any
	nextInvoked  bool
	statusCode   int
	responseBody string
	abortedError error
}

func NewMockContext() *mockContext {
	return &mockContext{
		headers: make(map[string]string),
		cookies: make(map[string]string),
		params:  make(map[string]string),
		queries: make(map[string]string),
		locals:  make(map[any]any),
	}
}

func (m *mockContext) Method() string                         { return "GET" }
func (m *mockContext) Path() string                           { return "/" }
func (m *mockContext) Param(name string, dv ...string) string { return m.params[name] }
func (m *mockContext) ParamsInt(key string, dv int) int       { return dv }
func (m *mockContext) Query(name string, dv string) string {
	val, ok := m.queries[name]
	if !ok {
		return dv
	}
	return val
}
func (m *mockContext) QueryInt(name string, dv int) int { return dv }
func (m *mockContext) Queries() map[string]string       { return m.queries }
func (m *mockContext) Body() []byte                     { return nil }
func (m *mockContext) Locals(key any, values ...any) any {
	if len(values) > 0 {
		m.locals[key] = values[0]
	}
	return m.locals[key]
}
func (m *mockContext) Render(name string, data any, layouts ...string) error {
	m.responseBody = fmt.Sprintf("rendered: %s", name)
	return nil
}
func (m *mockContext) Cookie(cookie *router.Cookie) {
	if cookie.Expires.Before(time.Now()) {
		// Simulate cookie deletion
		delete(m.cookies, cookie.Name)
		return
	}
	m.cookies[cookie.Name] = cookie.Value
}
func (m *mockContext) Cookies(name string, dv ...string) string {
	val, ok := m.cookies[name]
	if !ok {
		if len(dv) > 0 {
			return dv[0]
		}
		return ""
	}
	return val
}
func (m *mockContext) CookieParser(out any) error { return nil }
func (m *mockContext) Redirect(location string, status ...int) error {
	if len(status) > 0 {
		m.statusCode = status[0]
	} else {
		m.statusCode = http.StatusFound
	}
	return nil
}
func (m *mockContext) RedirectToRoute(routeName string, params router.ViewContext, status ...int) error {
	return m.Redirect("/some-route", status...)
}
func (m *mockContext) RedirectBack(fallback string, status ...int) error {
	return m.Redirect(fallback, status...)
}
func (m *mockContext) Get(key string, def any) any { return "" }

func (m *mockContext) Header(key string) string       { return m.headers[key] }
func (m *mockContext) Referer() string                { return "" }
func (m *mockContext) OriginalURL() string            { return "/" }
func (m *mockContext) Status(code int) router.Context { m.statusCode = code; return m }
func (m *mockContext) Send(body []byte) error         { m.responseBody = string(body); return nil }
func (m *mockContext) SendString(body string) error   { m.responseBody = body; return nil }
func (m *mockContext) JSON(code int, v any) error {
	m.statusCode = code
	m.responseBody = fmt.Sprintf("%v", v)
	return nil
}
func (m *mockContext) NoContent(code int) error             { m.statusCode = code; return nil }
func (m *mockContext) SetHeader(k, v string) router.Context { return m }
func (m *mockContext) GetString(key string, def string) string {
	val, ok := m.headers[key]
	if !ok {
		return def
	}
	return val
}
func (m *mockContext) GetInt(key string, def int) int    { return def }
func (m *mockContext) GetBool(key string, def bool) bool { return def }
func (m *mockContext) Set(key string, value any)         { m.locals[key] = value }
func (m *mockContext) Context() context.Context          { return nil }
func (m *mockContext) SetContext(_ context.Context)      {}
func (m *mockContext) Bind(v any) error                  { return nil }
func (m *mockContext) Next() error {
	m.nextInvoked = true
	return nil
}

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

	ctx := NewMockContext()
	ctx.headers["Authorization"] = "Bearer " + validToken

	err := middleware(ctx)
	if err != nil {
		t.Fatalf("unexpected error for valid token: %v", err)
	}
	if !ctx.nextInvoked {
		t.Errorf("expected nextInvoked to be true, but got false")
	}

	ctx = NewMockContext()
	err = middleware(ctx)
	if err == nil {
		t.Fatal("expected error for missing token, got nil")
	}
	if !strings.Contains(err.Error(), jwtware.ErrJWTMissingOrMalformed.Error()) {
		t.Errorf("expected missing token error, got: %v", err)
	}

	ctx = NewMockContext()
	ctx.headers["Authorization"] = "Bearer malformed.token.structure"
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

	ctx := NewMockContext()
	ctx.headers["Authorization"] = "Bearer " + expiredToken

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

	ctx := NewMockContext()
	ctx.queries["token"] = validToken

	err := middleware(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !ctx.nextInvoked {
		t.Errorf("expected Next to be invoked for valid token")
	}

	ctx = NewMockContext()
	ctx.params["jwt"] = validToken
	err = middleware(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	ctx = NewMockContext()
	ctx.cookies["jwt_cookie"] = validToken
	err = middleware(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// customPathMock overrides Path() from our base mockContext.
type customPathMock struct {
	*mockContext
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

	// context’s Path() returns "/public".
	ctx := &customPathMock{
		mockContext:  NewMockContext(),
		pathOverride: "/public",
	}

	// because Filter returns true for Path() == "/public",
	// the middleware should skip token checking and call ctx.Next()
	err := middleware(ctx)
	if err != nil {
		t.Fatalf("expected no error because Filter should skip, got %v", err)
	}
	if !ctx.nextInvoked {
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

	ctx := NewMockContext()
	ctx.headers["Authorization"] = "Bearer " + signed

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
	ctx := NewMockContext()
	ctx.headers["Authorization"] = "Bearer " + signed
	err = middleware(ctx)
	if err != nil {
		t.Fatalf("expected no error when kid=key-1 is used, got %v", err)
	}
}

func TestJWTWare_JWKSetURL(t *testing.T) {
	// Spin up a local HTTP test server that returns a static JWK Set.
	// We generate an HS256 JWK for demonstration. In real usage, you'd have RSA or EC JWKs.
	// For simplicity, let's just show structure. You can adapt to your use-case or library.

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

	// Test a request
	ctx := NewMockContext()
	ctx.headers["Authorization"] = "Bearer " + signed

	err = middleware(ctx)
	if err != nil {
		t.Fatalf("expected no error for valid JWK-signed token, got: %v", err)
	}
	if !ctx.nextInvoked {
		t.Error("expected nextInvoked to be true")
	}
}

// Example to show how a custom KeyFunc can override everything:
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

	// Even a valid token will fail
	validToken := generateToken(t, jwt.SigningMethodHS256, []byte("any"), jwt.MapClaims{"sub": "abc"})
	ctx := NewMockContext()
	ctx.headers["Authorization"] = "Bearer " + validToken
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
		setToken  func(*mockContext)
		wantError bool
	}{
		{
			name: "token in header -> success",
			setToken: func(ctx *mockContext) {
				ctx.headers["Authorization"] = "Bearer " + validToken
			},
		},
		{
			name: "token in query -> success",
			setToken: func(ctx *mockContext) {
				ctx.queries["jwt"] = validToken
			},
		},
		{
			name: "token in param -> success",
			setToken: func(ctx *mockContext) {
				ctx.params["token"] = validToken
			},
		},
		{
			name: "token in cookie -> success",
			setToken: func(ctx *mockContext) {
				ctx.cookies["jwt_cookie"] = validToken
			},
		},
		{
			name:      "no token anywhere -> error",
			setToken:  func(ctx *mockContext) {},
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := NewMockContext()
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

			if !ctx.nextInvoked {
				t.Errorf("middleware did not call Next() on success")
			}
		})
	}
}
