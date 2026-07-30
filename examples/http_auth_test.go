package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	exampleconfig "github.com/goliatone/go-auth-examples/config"
	gconfig "github.com/goliatone/go-config/config"
	"github.com/goliatone/go-logger/glog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var csrfFieldPattern = regexp.MustCompile(`name="_token" value="([^"]+)"`)

type authTestResponse struct {
	statusCode int
	header     http.Header
	cookies    []*http.Cookie
	body       []byte
}

func newExampleAuthTestApp(t *testing.T) *App {
	t.Helper()

	base := &exampleconfig.BaseConfig{
		Auth: exampleconfig.Auth{
			Audience:              []string{"example:user"},
			AuthScheme:            "Bearer",
			ContextKey:            "jwt",
			ExtendedTokenDuration: 48,
			Issuer:                "example",
			RejectedRouteDefault:  "/login",
			RejectedRouteKey:      "rejected_route",
			SigningKey:            "example-auth-test-signing-key-32-bytes",
			SigningMethod:         "HS256",
			TokenExpiration:       24,
			TokenLookup:           "header:Authorization,cookie:jwt",
		},
		Persistence: exampleconfig.Persistence{
			Driver:                "sqlite",
			Server:                "file",
			DSN:                   "file:" + filepath.Join(t.TempDir(), "example.db") + "?cache=shared",
			PingTimeoutExpression: "10s",
			OtelIdentifier:        "example-auth-test",
		},
		Views: exampleconfig.Views{
			CSSPath:   "css",
			JSPath:    "js",
			Embed:     true,
			Ext:       ".html",
			DirFS:     "views",
			AssetsDir: "public",
			URLPrefix: "assets",
		},
	}
	app := &App{
		config: gconfig.New(base),
		logger: glog.NewLogger(
			glog.WithLoggerTypeJSON(),
			glog.WithWriter(io.Discard),
		),
	}

	require.NoError(t, WithPersistence(t.Context(), app))
	t.Cleanup(func() {
		require.NoError(t, app.bunDB.Close())
	})
	require.NoError(t, WithHTTPServer(t.Context(), app))
	require.NoError(t, WithHTTPAuth(t.Context(), app))
	return app
}

func performAuthRequest(t *testing.T, app *App, request *http.Request) authTestResponse {
	t.Helper()

	response, err := app.srv.WrappedRouter().Test(request, -1)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	return authTestResponse{
		statusCode: response.StatusCode,
		header:     response.Header.Clone(),
		cookies:    response.Cookies(),
		body:       body,
	}
}

func loginRequest(t *testing.T, token string) *http.Request {
	t.Helper()

	form := url.Values{
		"identifier": {"admin@example.com"},
		"password":   {"adminpass"},
	}
	if token != "" {
		form.Set("_token", token)
	}
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"http://example.com/login",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	return request
}

func TestExampleLoginUsesSharedPackageCSRFContract(t *testing.T) {
	app := newExampleAuthTestApp(t)

	getResponse := performAuthRequest(t, app, httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"http://example.com/login",
		nil,
	))
	require.Equal(t, http.StatusOK, getResponse.statusCode)
	match := csrfFieldPattern.FindSubmatch(getResponse.body)
	require.Len(t, match, 2)
	token := string(match[1])
	require.NotEmpty(t, token)
	assert.Equal(t, token, getResponse.header.Get("X-CSRF-Token"))

	missingResponse := performAuthRequest(t, app, loginRequest(t, ""))
	assert.Equal(t, http.StatusForbidden, missingResponse.statusCode)

	tamperedResponse := performAuthRequest(t, app, loginRequest(t, "tampered"))
	assert.Equal(t, http.StatusForbidden, tamperedResponse.statusCode)

	loginResponse := performAuthRequest(t, app, loginRequest(t, token))
	require.Equal(t, http.StatusSeeOther, loginResponse.statusCode, string(loginResponse.body))
	assert.Equal(t, "/", loginResponse.header.Get("Location"))
	var authCookie *http.Cookie
	for _, cookie := range loginResponse.cookies {
		if cookie.Name == "jwt" {
			authCookie = cookie
			break
		}
	}
	require.NotNil(t, authCookie)
	assert.NotEmpty(t, authCookie.Value)
	assert.True(t, authCookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, authCookie.SameSite)
}
