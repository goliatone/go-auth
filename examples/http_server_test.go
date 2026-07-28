package main

import (
	"context"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	exampleconfig "github.com/goliatone/go-auth-examples/config"
	gconfig "github.com/goliatone/go-config/config"
	gerrors "github.com/goliatone/go-errors"
	"github.com/goliatone/go-logger/glog"
	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newHTTPServerTestApp(t *testing.T) *App {
	t.Helper()

	base := &exampleconfig.BaseConfig{
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
	require.NoError(t, WithHTTPServer(context.Background(), app))
	app.srv.Router().Get("/login", func(ctx router.Context) error {
		return renderWithGlobals(ctx, "login", router.ViewContext{
			"title": "Sign In",
		})
	})
	return app
}

func performExampleRequest(t *testing.T, app *App, method, target string) (int, http.Header, string) {
	t.Helper()

	resp, err := app.srv.WrappedRouter().Test(httptest.NewRequest(method, target, nil))
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, string(body)
}

func TestWithHTTPServerServesNamespacedAssets(t *testing.T) {
	app := newHTTPServerTestApp(t)

	status, _, body := performExampleRequest(t, app, http.MethodGet, "/login")
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, `href="/assets/css/main-CoC3SGxJ.css"`)
	assert.Contains(t, body, `src="/assets/js/main-Dop5R4UJ.js"`)
	assert.Contains(t, body, `href="/assets/icon_dark.svg"`)
	assert.Contains(t, body, `src="/assets/logo_dark.svg"`)
	assert.NotContains(t, body, "is valid?")
	assert.NotContains(t, body, "SigningString")

	tests := []struct {
		target      string
		contentType string
	}{
		{target: "/assets/css/main-CoC3SGxJ.css", contentType: "text/css"},
		{target: "/assets/js/main-Dop5R4UJ.js", contentType: "text/javascript"},
		{target: "/assets/logo_dark.svg", contentType: "image/svg+xml"},
		{target: "/assets/icon_dark.svg", contentType: "image/svg+xml"},
		{target: "/assets/favicon.ico", contentType: "image/"},
	}
	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			assetStatus, headers, _ := performExampleRequest(t, app, http.MethodGet, test.target)
			assert.Equal(t, http.StatusOK, assetStatus)
			assert.Contains(t, headers.Get("Content-Type"), test.contentType)

			headStatus, _, _ := performExampleRequest(t, app, http.MethodHead, test.target)
			assert.Equal(t, http.StatusOK, headStatus)
		})
	}

	status, _, body = performExampleRequest(t, app, http.MethodGet, "/")
	assert.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, "Home Renderer")

	status, _, _ = performExampleRequest(t, app, http.MethodGet, "/css/main-CoC3SGxJ.css")
	assert.Equal(t, http.StatusNotFound, status)
}

func TestNewAssetFileSystemPrefersDiskAndRetainsEmbeddedFallbacks(t *testing.T) {
	diskDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(diskDir, "css"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(diskDir, "css", "main-CoC3SGxJ.css"),
		[]byte("disk override"),
		0o644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(diskDir, "css", "development-only.css"),
		[]byte("development only"),
		0o644,
	))

	assets := newAssetFileSystem(embeddedFS, "public", diskDir)

	body, err := fs.ReadFile(assets, "css/main-CoC3SGxJ.css")
	require.NoError(t, err)
	assert.Equal(t, "disk override", string(body))

	_, err = fs.ReadFile(assets, "logo_dark.svg")
	require.NoError(t, err, "embedded fallback should remain visible")

	entries, err := fs.ReadDir(assets, "css")
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	assert.Contains(t, names, "main-CoC3SGxJ.css")
	assert.Contains(t, names, "development-only.css")
}

func TestResolveExampleDirectoryFromSupportedWorkingDirectories(t *testing.T) {
	repositoryRoot := t.TempDir()
	exampleRoot := filepath.Join(repositoryRoot, "examples")
	publicDir := filepath.Join(exampleRoot, "public")
	require.NoError(t, os.MkdirAll(publicDir, 0o755))

	assert.Equal(
		t,
		publicDir,
		resolveExampleDirectoryFrom(repositoryRoot, "public"),
	)
	assert.Equal(
		t,
		publicDir,
		resolveExampleDirectoryFrom(exampleRoot, "public"),
	)
}

func TestWithHTTPServerRejectsRootAssetNamespace(t *testing.T) {
	base := &exampleconfig.BaseConfig{
		Views: exampleconfig.Views{
			Embed:     true,
			Ext:       ".html",
			DirFS:     "views",
			AssetsDir: "public",
		},
	}
	app := &App{
		config: gconfig.New(base),
		logger: glog.NewLogger(
			glog.WithLoggerTypeJSON(),
			glog.WithWriter(io.Discard),
		),
	}

	err := WithHTTPServer(context.Background(), app)
	require.Error(t, err)
	var richErr *gerrors.Error
	require.ErrorAs(t, err, &richErr)
	assert.Equal(t, gerrors.CategoryValidation, richErr.Category)
	assert.Equal(t, startupCodeAssetPrefixInvalid, richErr.TextCode)
	assert.Equal(t, "views.url_prefix", richErr.Metadata["field"])
}
