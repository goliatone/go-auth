package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	csrfmw "github.com/goliatone/go-auth/middleware/csrf"
	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/require"
)

func TestProviderSessionHTTPResolvesPrincipalAndEnforcesCSRF(t *testing.T) {
	principal := managerTestPrincipal(t)
	principal, err := principal.BindLocalSessionID("local-session")
	require.NoError(t, err)
	resolver := fixedProviderSessionResolver{
		session: auth.ProviderSession{
			ID: "internal", LocalSessionID: "local-session",
			Principal: auth.NewPrincipalSnapshot(principal), Status: auth.ProviderSessionAvailable,
		},
		principal: principal,
	}
	httpSessions := newProviderSessionHTTPForTest(t, resolver)
	server := router.NewHTTPServer().(*router.HTTPServer)
	server.Router().Get("/session", func(c router.Context) error {
		current, ok := auth.ProviderSessionFromContext(c.Context())
		if !ok {
			return c.SendStatus(http.StatusInternalServerError)
		}
		sessionID, _ := c.Locals("session_id").(string)
		if current.Principal.ApplicationSubject() != "user-1" || sessionID != "local-session" {
			return c.SendStatus(http.StatusInternalServerError)
		}
		token, _ := c.Locals(csrfmw.DefaultContextKey).(string)
		return c.SendString(token)
	}, httpSessions.Middleware())
	server.Router().Post("/session", func(c router.Context) error {
		return c.SendStatus(http.StatusOK)
	}, httpSessions.Middleware())

	getReq := httptest.NewRequest(http.MethodGet, "https://app.example.com/session", nil)
	getReq.AddCookie(&http.Cookie{Name: auth.DefaultProviderSessionCookieName, Value: "opaque-handle"})
	getResp := httptest.NewRecorder()
	server.WrappedRouter().ServeHTTP(getResp, getReq)
	require.Equal(t, http.StatusOK, getResp.Code)
	csrfToken := strings.TrimSpace(getResp.Body.String())
	require.NotEmpty(t, csrfToken)

	postReq := httptest.NewRequest(http.MethodPost, "https://app.example.com/session", nil)
	postReq.Header.Set("Origin", "https://app.example.com")
	postReq.AddCookie(&http.Cookie{Name: auth.DefaultProviderSessionCookieName, Value: "opaque-handle"})
	postResp := httptest.NewRecorder()
	server.WrappedRouter().ServeHTTP(postResp, postReq)
	require.Equal(t, http.StatusBadRequest, postResp.Code)

	validReq := httptest.NewRequest(http.MethodPost, "https://app.example.com/session", nil)
	validReq.Header.Set("Origin", "https://app.example.com")
	validReq.Header.Set(csrfmw.DefaultHeaderName, csrfToken)
	validReq.AddCookie(&http.Cookie{Name: auth.DefaultProviderSessionCookieName, Value: "opaque-handle"})
	validResp := httptest.NewRecorder()
	server.WrappedRouter().ServeHTTP(validResp, validReq)
	require.Equal(t, http.StatusOK, validResp.Code)
}

func TestProviderSessionHTTPRejectsConflictingCredentials(t *testing.T) {
	httpSessions := newProviderSessionHTTPForTest(t, fixedProviderSessionResolver{err: errors.New("should not resolve")})
	server := router.NewHTTPServer().(*router.HTTPServer)
	server.Router().Get("/session", func(c router.Context) error {
		return c.SendStatus(http.StatusOK)
	}, httpSessions.Middleware())

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/session", nil)
	req.Header.Set("Authorization", "Bearer local-token")
	req.AddCookie(&http.Cookie{Name: auth.DefaultProviderSessionCookieName, Value: "opaque-handle"})
	resp := httptest.NewRecorder()
	server.WrappedRouter().ServeHTTP(resp, req)
	require.Equal(t, http.StatusUnauthorized, resp.Code)
}

func TestProviderSessionHTTPClearsUnusableCookie(t *testing.T) {
	httpSessions := newProviderSessionHTTPForTest(t, fixedProviderSessionResolver{err: auth.ErrProviderSessionExpired})
	server := router.NewHTTPServer().(*router.HTTPServer)
	server.Router().Get("/session", func(c router.Context) error {
		return c.SendStatus(http.StatusOK)
	}, httpSessions.Middleware())

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/session", nil)
	req.AddCookie(&http.Cookie{Name: auth.DefaultProviderSessionCookieName, Value: "opaque-handle"})
	resp := httptest.NewRecorder()
	server.WrappedRouter().ServeHTTP(resp, req)
	require.Equal(t, http.StatusUnauthorized, resp.Code)
	setCookie := resp.Header().Get("Set-Cookie")
	require.Contains(t, setCookie, auth.DefaultProviderSessionCookieName+"=")
	require.Contains(t, setCookie, "Path=/")
	require.Contains(t, setCookie, "HttpOnly")
	require.Contains(t, setCookie, "Secure")
}

func TestProviderSessionHTTPValidatesHostCookiePolicy(t *testing.T) {
	_, err := auth.NewProviderSessionHTTP(auth.ProviderSessionHTTPConfig{
		Resolver: fixedProviderSessionResolver{},
		Binding: auth.ProviderSessionBinding{
			Host: "app.example.com", ApplicationID: "app", Environment: "test",
			Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
		},
		Cookie: router.Cookie{
			Name: auth.DefaultProviderSessionCookieName, Path: "/", Domain: "example.com",
			Secure: true, HTTPOnly: true, SameSite: router.CookieSameSiteLaxMode,
		},
		CookieDuration: time.Hour,
		AllowDomain:    true,
		CSRF:           csrfmw.Config{SecureKey: []byte("01234567890123456789012345678901")},
	})
	require.ErrorIs(t, err, auth.ErrProviderSessionInvalid)
}

func newProviderSessionHTTPForTest(t *testing.T, resolver auth.ProviderSessionResolver) *auth.ProviderSessionHTTP {
	t.Helper()
	httpSessions, err := auth.NewProviderSessionHTTP(auth.ProviderSessionHTTPConfig{
		Resolver: resolver,
		Binding: auth.ProviderSessionBinding{
			Host: "app.example.com", ApplicationID: "app", Environment: "test",
			Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
		},
		CookieDuration: time.Hour,
		LocalJWTCookie: "auth",
		CSRF: csrfmw.Config{
			SecureKey:  []byte("01234567890123456789012345678901"),
			Expiration: time.Hour,
		},
	})
	require.NoError(t, err)
	return httpSessions
}

type fixedProviderSessionResolver struct {
	session   auth.ProviderSession
	principal auth.AuthenticatedPrincipal
	err       error
}

func (r fixedProviderSessionResolver) ResolveProviderSession(context.Context, auth.Secret, auth.ProviderSessionBinding) (auth.ProviderSession, auth.AuthenticatedPrincipal, error) {
	return r.session, r.principal, r.err
}
