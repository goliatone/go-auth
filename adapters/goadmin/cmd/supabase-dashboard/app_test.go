package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
)

func TestBuildApplicationInitializesAdminAndOIDCRoutes(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/v1/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(oidc.DiscoveryMetadata{
				Issuer:                   provider.URL + "/auth/v1",
				AuthorizationEndpoint:    provider.URL + "/auth/v1/oauth/authorize",
				TokenEndpoint:            provider.URL + "/auth/v1/oauth/token",
				JWKSURI:                  provider.URL + "/auth/v1/.well-known/jwks.json",
				Algorithms:               []string{"RS256"},
				TokenEndpointAuthMethods: []string{"client_secret_basic"},
			})
		case "/auth/v1/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "test-key",
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	projectURL, err := parseApplicationURL(provider.URL, true)
	if err != nil {
		t.Fatalf("parse provider URL: %v", err)
	}
	appURL, err := parseApplicationURL("http://127.0.0.1:8081", true)
	if err != nil {
		t.Fatalf("parse app URL: %v", err)
	}
	cfg := runtimeConfig{
		Address:               defaultAddress,
		AppURL:                appURL,
		DatabaseDSN:           "file:" + filepath.Join(t.TempDir(), "dashboard.db") + "?cache=shared&_pragma=foreign_keys(1)",
		ProjectURL:            projectURL,
		ClientID:              "dashboard-client",
		ClientSecret:          auth.NewSecret("client-secret"),
		TokenEndpointAuth:     oidc.TokenEndpointAuthClientSecretBasic,
		IDTokenAudience:       []string{"dashboard-client"},
		AccessTokenAudience:   []string{"authenticated"},
		AllowedAlgorithms:     []string{"RS256"},
		AllowInsecureLoopback: true,
		SigningKey:            auth.NewSecret(strings.Repeat("k", 32)),
	}

	app, err := buildApplication(context.Background(), cfg)
	if err != nil {
		t.Fatalf("buildApplication: %v", err)
	}

	assertResponse := func(target string, wantStatus int, wantBody, forbiddenBody string) {
		t.Helper()
		response, err := app.testRequest(httptest.NewRequest(http.MethodGet, target, nil))
		if err != nil {
			t.Fatalf("request %s: %v", target, err)
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			t.Fatalf("read %s response: %v", target, readErr)
		}
		if closeErr != nil {
			t.Fatalf("close %s response: %v", target, closeErr)
		}
		if response.StatusCode != wantStatus {
			t.Fatalf("%s status = %d, want %d; body=%s", target, response.StatusCode, wantStatus, body)
		}
		if wantBody != "" && !strings.Contains(string(body), wantBody) {
			t.Fatalf("%s response does not contain %q: %s", target, wantBody, body)
		}
		if forbiddenBody != "" && strings.Contains(string(body), forbiddenBody) {
			t.Fatalf("%s response exposed forbidden value %q", target, forbiddenBody)
		}
	}

	assertResponse("/healthz", http.StatusOK, `"status":"ok"`, "")
	assertResponse("/admin/login", http.StatusOK, "Supabase", "client-secret")
	assertResponse("/admin/sso/providers", http.StatusOK, `"key":"supabase"`, "client-secret")
	assertResponse("/admin/dashboard", http.StatusFound, "", "")

	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := app.Close(closeCtx); err != nil {
		t.Fatalf("close application: %v", err)
	}
}
