package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goliatone/go-auth"
	csrfmw "github.com/goliatone/go-auth/middleware/csrf"
	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/mock"
)

type browserTestConfig struct{}

func (browserTestConfig) GetSigningKey() string         { return "test-secret" }
func (browserTestConfig) GetSigningMethod() string      { return "HS256" }
func (browserTestConfig) GetContextKey() string         { return "auth" }
func (browserTestConfig) GetTokenExpiration() int       { return 24 }
func (browserTestConfig) GetExtendedTokenDuration() int { return 48 }
func (browserTestConfig) GetTokenLookup() string {
	return "header:Authorization,cookie:auth"
}
func (browserTestConfig) GetAuthScheme() string       { return "Bearer" }
func (browserTestConfig) GetIssuer() string           { return "go-auth-tests" }
func (browserTestConfig) GetAudience() []string       { return []string{"go-auth-tests"} }
func (browserTestConfig) GetRejectedRouteKey() string { return "redirect" }
func (browserTestConfig) GetRejectedRouteDefault() string {
	return "/login"
}

type memoryCSRFStore struct {
	values map[string]string
}

type browserIdentity struct{}

func (browserIdentity) ID() string       { return "user-1" }
func (browserIdentity) Username() string { return "user-1" }
func (browserIdentity) Email() string    { return "user-1@example.com" }
func (browserIdentity) Role() string     { return string(auth.RoleAdmin) }

type browserIdentityProvider struct{}

func (browserIdentityProvider) VerifyIdentity(_ context.Context, _, _ string) (auth.Identity, error) {
	return browserIdentity{}, nil
}

func (browserIdentityProvider) FindIdentityByIdentifier(_ context.Context, _ string) (auth.Identity, error) {
	return browserIdentity{}, nil
}

func (s *memoryCSRFStore) Get(key string) (string, error) {
	if s == nil || s.values == nil {
		return "", nil
	}
	return s.values[key], nil
}

func (s *memoryCSRFStore) Set(key, value string, _ time.Duration) error {
	if s.values == nil {
		s.values = map[string]string{}
	}
	s.values[key] = value
	return nil
}

func (s *memoryCSRFStore) Delete(key string) error {
	delete(s.values, key)
	return nil
}

func TestNewHTTPAuthenticatorRejectsInvalidCookieTemplate(t *testing.T) {
	_, err := auth.NewHTTPAuthenticator(
		new(MockAuthenticator),
		browserTestConfig{},
		auth.WithAuthCookieTemplate(router.Cookie{SameSite: router.CookieSameSiteNoneMode}),
	)
	if err == nil {
		t.Fatalf("expected invalid cookie template to fail")
	}
}

func TestGetRedirectOrDefaultRejectsExternalReferer(t *testing.T) {
	httpAuth, err := auth.NewHTTPAuthenticator(new(MockAuthenticator), browserTestConfig{})
	if err != nil {
		t.Fatalf("NewHTTPAuthenticator error: %v", err)
	}

	mockCtx := router.NewMockContext()
	mockCtx.On("Referer").Return("https://evil.example/phish")
	mockCtx.On("Cookie", mock.MatchedBy(mockCookieDeleteMatcher("redirect"))).Return()

	redirect := httpAuth.GetRedirectOrDefault(mockCtx)
	if redirect != "/login" {
		t.Fatalf("expected config default redirect, got %q", redirect)
	}
}

func TestProtectedBrowserRouteEnforcesCSRFForCookieAuth(t *testing.T) {
	cfg := browserTestConfig{}
	store := &memoryCSRFStore{}
	auther := auth.NewAuthenticator(browserIdentityProvider{}, cfg)
	httpAuth, err := auth.NewHTTPAuthenticator(auther, cfg)
	if err != nil {
		t.Fatalf("NewHTTPAuthenticator error: %v", err)
	}

	server := router.NewHTTPServer().(*router.HTTPServer)
	server.Router().Get("/protected", func(c router.Context) error {
		token, _ := c.Locals(csrfmw.DefaultContextKey).(string)
		return c.SendString(token)
	}, httpAuth.ProtectedBrowserRoute(cfg, authErrorHandler(t), auth.BrowserProtectionConfig{
		CSRF: csrfmw.Config{Storage: store},
	}))
	server.Router().Post("/protected", func(c router.Context) error {
		return c.SendStatus(http.StatusOK)
	}, httpAuth.ProtectedBrowserRoute(cfg, authErrorHandler(t), auth.BrowserProtectionConfig{
		CSRF: csrfmw.Config{Storage: store},
	}))

	token, err := auther.TokenService().Generate(browserIdentity{}, nil)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	getReq := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	getReq.Host = "example.com"
	getReq.AddCookie(&http.Cookie{Name: "auth", Value: token})
	getResp := httptest.NewRecorder()
	server.WrappedRouter().ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusOK {
		t.Fatalf("expected GET to succeed, got %d", getResp.Code)
	}
	csrfToken := getResp.Body.String()
	if csrfToken == "" {
		t.Fatalf("expected GET to provide csrf token")
	}
	if headerToken := strings.TrimSpace(getResp.Header().Get(csrfmw.DefaultHeaderName)); headerToken == "" {
		t.Fatalf("expected GET to emit csrf header")
	} else if headerToken != csrfToken {
		t.Fatalf("expected GET csrf header to match rendered token")
	}

	postReq := httptest.NewRequest(http.MethodPost, "http://example.com/protected", nil)
	postReq.Host = "example.com"
	postReq.Header.Set("Origin", "http://example.com")
	postReq.AddCookie(&http.Cookie{Name: "auth", Value: token})
	postResp := httptest.NewRecorder()
	server.WrappedRouter().ServeHTTP(postResp, postReq)
	if postResp.Code != http.StatusBadRequest {
		t.Fatalf("expected POST without CSRF token to fail, got %d", postResp.Code)
	}

	validPostReq := httptest.NewRequest(http.MethodPost, "http://example.com/protected", nil)
	validPostReq.Host = "example.com"
	validPostReq.Header.Set("Origin", "http://example.com")
	validPostReq.Header.Set(csrfmw.DefaultHeaderName, csrfToken)
	validPostReq.AddCookie(&http.Cookie{Name: "auth", Value: token})
	validPostResp := httptest.NewRecorder()
	server.WrappedRouter().ServeHTTP(validPostResp, validPostReq)
	if validPostResp.Code != http.StatusOK {
		t.Fatalf("expected POST with CSRF token to succeed, got %d", validPostResp.Code)
	}
}

func TestProtectedBrowserRouteAllowsBearerOnlyPostWithoutCSRF(t *testing.T) {
	cfg := browserTestConfig{}
	store := &memoryCSRFStore{}
	auther := auth.NewAuthenticator(browserIdentityProvider{}, cfg)
	httpAuth, err := auth.NewHTTPAuthenticator(auther, cfg)
	if err != nil {
		t.Fatalf("NewHTTPAuthenticator error: %v", err)
	}

	server := router.NewHTTPServer().(*router.HTTPServer)
	server.Router().Post("/protected", func(c router.Context) error {
		return c.SendStatus(http.StatusOK)
	}, httpAuth.ProtectedBrowserRoute(cfg, authErrorHandler(t), auth.BrowserProtectionConfig{
		CSRF: csrfmw.Config{Storage: store},
	}))

	req := httptest.NewRequest(http.MethodPost, "http://example.com/protected", nil)
	req.Host = "example.com"
	token, err := auther.TokenService().Generate(browserIdentity{}, nil)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp := httptest.NewRecorder()
	server.WrappedRouter().ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected bearer POST without CSRF to succeed, got %d", resp.Code)
	}
}

func TestProtectedBrowserRouteSupportsDirectWrapperComposition(t *testing.T) {
	cfg := browserTestConfig{}
	store := &memoryCSRFStore{}
	auther := auth.NewAuthenticator(browserIdentityProvider{}, cfg)
	httpAuth, err := auth.NewHTTPAuthenticator(auther, cfg)
	if err != nil {
		t.Fatalf("NewHTTPAuthenticator error: %v", err)
	}

	token, err := auther.TokenService().Generate(browserIdentity{}, nil)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	protected := httpAuth.ProtectedBrowserRoute(cfg, authErrorHandler(t), auth.BrowserProtectionConfig{
		CSRF: csrfmw.Config{Storage: store},
	})(func(c router.Context) error {
		return c.SendString("wrapped-ok")
	})

	server := router.NewHTTPServer().(*router.HTTPServer)
	server.Router().Get("/wrapped", protected)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/wrapped", nil)
	req.Host = "example.com"
	req.AddCookie(&http.Cookie{Name: "auth", Value: token})
	resp := httptest.NewRecorder()
	server.WrappedRouter().ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected direct wrapper GET to succeed, got %d", resp.Code)
	}
	if resp.Body.String() != "wrapped-ok" {
		t.Fatalf("expected wrapped handler body, got %q", resp.Body.String())
	}
}

func TestStatefulCSRFFailsWithoutSessionKey(t *testing.T) {
	server := router.NewHTTPServer().(*router.HTTPServer)
	store := &memoryCSRFStore{}
	server.Router().Post("/submit", func(c router.Context) error {
		return c.SendStatus(http.StatusOK)
	}, csrfmw.New(csrfmw.Config{
		Storage:      store,
		ErrorHandler: func(c router.Context, err error) error { return c.Status(http.StatusForbidden).SendString(err.Error()) },
	}))

	req := httptest.NewRequest(http.MethodPost, "http://example.com/submit", nil)
	resp := httptest.NewRecorder()
	server.WrappedRouter().ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected missing session key to fail, got %d", resp.Code)
	}
	if resp.Body.String() != csrfmw.ErrSessionKeyMissing.Error() {
		t.Fatalf("expected ErrSessionKeyMissing, got %q", resp.Body.String())
	}
}

func authErrorHandler(t *testing.T) func(router.Context, error) error {
	t.Helper()
	return func(c router.Context, err error) error {
		if err != nil {
			return c.Status(http.StatusUnauthorized).SendString(err.Error())
		}
		return c.Status(http.StatusUnauthorized).SendString("unauthorized")
	}
}

func mockCookieDeleteMatcher(name string) func(*router.Cookie) bool {
	return func(c *router.Cookie) bool {
		return c.Name == name && c.Value == "" && c.HTTPOnly
	}
}
