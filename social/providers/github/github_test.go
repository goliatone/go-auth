package github

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/goliatone/go-auth/social"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderAuthCodeURL(t *testing.T) {
	provider := New(Config{
		ClientID:    "client-id",
		CallbackURL: "https://example.com/callback",
	})

	authURL := provider.AuthCodeURL("state-token", social.WithScopes("repo"), social.WithPKCE("challenge", "S256"))

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)

	query := parsed.Query()
	assert.Equal(t, "client-id", query.Get("client_id"))
	assert.Equal(t, "https://example.com/callback", query.Get("redirect_uri"))
	assert.Equal(t, "state-token", query.Get("state"))
	assert.Equal(t, "challenge", query.Get("code_challenge"))
	assert.Equal(t, "S256", query.Get("code_challenge_method"))

	scope := query.Get("scope")
	assert.Contains(t, scope, "read:user")
	assert.Contains(t, scope, "user:email")
	assert.Contains(t, scope, "repo")
}

func TestProviderExchangeAndUserInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			assert.Equal(t, http.MethodPost, r.Method)
			body, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			values, err := url.ParseQuery(string(body))
			assert.NoError(t, err)
			assert.Equal(t, "client-id", values.Get("client_id"))
			assert.Equal(t, "client-secret", values.Get("client_secret"))
			assert.Equal(t, "auth-code", values.Get("code"))
			assert.Equal(t, "verifier", values.Get("code_verifier"))

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "token",
				"token_type":   "bearer",
				"scope":        "user:email,read:user",
			})
		case "/user":
			assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         1234,
				"login":      "octo",
				"name":       "Octo Cat",
				"email":      "",
				"avatar_url": "https://example.com/avatar.png",
				"html_url":   "https://github.com/octo",
			})
		case "/user/emails":
			assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"email": "octo@example.com", "primary": true, "verified": true},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	provider := New(Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		CallbackURL:  "https://example.com/callback",
		AuthURL:      server.URL + "/login/oauth/authorize",
		TokenURL:     server.URL + "/login/oauth/access_token",
		UserURL:      server.URL + "/user",
		EmailsURL:    server.URL + "/user/emails",
	})

	token, err := provider.Exchange(context.Background(), "auth-code", social.WithCodeVerifier("verifier"))
	require.NoError(t, err)
	assert.Equal(t, "token", token.AccessToken)

	profile, err := provider.UserInfo(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "1234", profile.ProviderUserID)
	assert.Equal(t, "octo@example.com", profile.Email)
	assert.True(t, profile.EmailVerified)
	assert.Equal(t, "octo", profile.Username)
}

func TestProviderExchangeErrorNormalized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":             "bad_verification_code",
			"error_description": "bad code",
		})
	}))
	defer server.Close()

	provider := New(Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		CallbackURL:  "https://example.com/callback",
		TokenURL:     server.URL,
	})

	_, err := provider.Exchange(context.Background(), "bad-code")
	require.Error(t, err)

	var perr *social.ProviderError
	require.True(t, errors.As(err, &perr))
	assert.Equal(t, "github", perr.Provider)
	assert.Equal(t, "exchange", perr.Operation)
	assert.Equal(t, http.StatusBadRequest, perr.Status)
	assert.Equal(t, "bad_verification_code", perr.Code)
}
