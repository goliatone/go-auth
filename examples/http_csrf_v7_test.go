package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
)

func TestExamplePongo2V7CSRFLiveHTTP(t *testing.T) {
	app := newExampleAuthTestApp(t)
	ProtectedRoutes(app)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	native := app.srv.WrappedRouter()
	done := make(chan error, 1)
	go func() { done <- native.Listener(listener, fiber.ListenConfig{DisableStartupMessage: true}) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		require.NoError(t, app.srv.Shutdown(ctx))
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-ctx.Done():
			_ = listener.Close()
			t.Fatal("auth listener did not stop")
		}
	})
	base := "http://" + listener.Addr().String()
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(client.CloseIdleConnections)
	request := func(method, path, body string, cookie *http.Cookie) authTestResponse {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, base+path, strings.NewReader(body))
		require.NoError(t, err)
		if method == http.MethodPost {
			req.Header.Set("Origin", base)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		data, readErr := io.ReadAll(resp.Body)
		require.NoError(t, resp.Body.Close())
		require.NoError(t, readErr)
		return authTestResponse{statusCode: resp.StatusCode, header: resp.Header.Clone(), cookies: resp.Cookies(), body: data}
	}
	unauthenticated := request(http.MethodGet, "/protected-page", "", nil)
	require.Equal(t, http.StatusFound, unauthenticated.statusCode)
	require.Equal(t, "/login", unauthenticated.header.Get("Location"))
	page := request(http.MethodGet, "/login", "", nil)
	require.Equal(t, http.StatusOK, page.statusCode, string(page.body))
	match := csrfFieldPattern.FindSubmatch(page.body)
	require.Len(t, match, 2)
	token := string(match[1])
	require.NotEmpty(t, token)
	require.Equal(t, token, page.header.Get("X-CSRF-Token"))
	require.Contains(t, string(page.body), `<meta name="csrf-token" content="`+token+`">`)
	for _, supplied := range []string{"", "tampered"} {
		form := url.Values{"identifier": {"admin@example.com"}, "password": {"adminpass"}, "_token": {supplied}}
		denied := request(http.MethodPost, "/login", form.Encode(), nil)
		require.Equal(t, http.StatusForbidden, denied.statusCode, string(denied.body))
	}
	form := url.Values{"identifier": {"admin@example.com"}, "password": {"adminpass"}, "_token": {token}}
	login := request(http.MethodPost, "/login", form.Encode(), nil)
	require.Equal(t, http.StatusSeeOther, login.statusCode, string(login.body))
	require.Equal(t, "/", login.header.Get("Location"))
	var jwt *http.Cookie
	for _, cookie := range login.cookies {
		if cookie.Name == "jwt" {
			jwt = cookie
		}
	}
	require.NotNil(t, jwt)
	require.True(t, jwt.HttpOnly)
	protected := request(http.MethodGet, "/protected-page", "", jwt)
	require.Equal(t, http.StatusOK, protected.statusCode, string(protected.body))
	require.Contains(t, string(protected.body), "Actor ID")
	require.NotContains(t, string(protected.body), "No actor context was found")
	asset := request(http.MethodGet, "/assets/css/main.css", "", nil)
	require.Equal(t, http.StatusOK, asset.statusCode)
	require.Contains(t, asset.header.Get("Content-Type"), "text/css")
}
