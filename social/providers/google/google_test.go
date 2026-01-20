package google

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/goliatone/go-auth/social"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderAuthCodeURL(t *testing.T) {
	provider := New(Config{
		ClientID:    "client-id",
		CallbackURL: "https://example.com/callback",
	})

	authURL := provider.AuthCodeURL("state-token", social.WithPKCE("challenge", "S256"), social.WithPrompt("consent"))

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)

	query := parsed.Query()
	assert.Equal(t, "client-id", query.Get("client_id"))
	assert.Equal(t, "https://example.com/callback", query.Get("redirect_uri"))
	assert.Equal(t, "state-token", query.Get("state"))
	assert.Equal(t, "code", query.Get("response_type"))
	assert.Equal(t, "offline", query.Get("access_type"))
	assert.Equal(t, "consent", query.Get("prompt"))
	assert.Equal(t, "challenge", query.Get("code_challenge"))
	assert.Equal(t, "S256", query.Get("code_challenge_method"))

	scope := query.Get("scope")
	assert.Contains(t, scope, "openid")
	assert.Contains(t, scope, "email")
	assert.Contains(t, scope, "profile")
}

func TestProviderExchangeUserInfoAndRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			body, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			values, err := url.ParseQuery(string(body))
			assert.NoError(t, err)

			grantType := values.Get("grant_type")
			w.Header().Set("Content-Type", "application/json")
			if grantType == "authorization_code" {
				assert.Equal(t, "client-id", values.Get("client_id"))
				assert.Equal(t, "client-secret", values.Get("client_secret"))
				assert.Equal(t, "auth-code", values.Get("code"))
				assert.Equal(t, "verifier", values.Get("code_verifier"))
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token":  "token",
					"token_type":    "Bearer",
					"expires_in":    3600,
					"refresh_token": "refresh-token",
					"scope":         "openid email profile",
					"id_token":      "id-token",
				})
				return
			}

			if grantType == "refresh_token" {
				assert.Equal(t, "refresh-token", values.Get("refresh_token"))
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "refreshed",
					"token_type":   "Bearer",
					"expires_in":   7200,
					"scope":        "openid email profile",
				})
				return
			}

			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "unsupported_grant"})
		case "/userinfo":
			assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":            "user-1",
				"email":          "user@example.com",
				"email_verified": true,
				"name":           "User Example",
				"given_name":     "User",
				"family_name":    "Example",
				"picture":        "https://example.com/avatar.png",
				"locale":         "en",
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
		TokenURL:     server.URL + "/token",
		UserInfoURL:  server.URL + "/userinfo",
	})

	token, err := provider.Exchange(context.Background(), "auth-code", social.WithCodeVerifier("verifier"))
	require.NoError(t, err)
	assert.Equal(t, "token", token.AccessToken)
	assert.Equal(t, "refresh-token", token.RefreshToken)
	assert.True(t, token.ExpiresAt.After(time.Now()))

	profile, err := provider.UserInfo(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "user-1", profile.ProviderUserID)
	assert.Equal(t, "user@example.com", profile.Email)
	assert.True(t, profile.EmailVerified)
	assert.Equal(t, "User", profile.FirstName)

	refreshed, err := provider.RefreshToken(context.Background(), "refresh-token")
	require.NoError(t, err)
	assert.Equal(t, "refreshed", refreshed.AccessToken)
	assert.True(t, refreshed.ExpiresAt.After(time.Now()))
}

func TestProviderUserInfoErrorNormalized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":    401,
				"message": "Invalid Credentials",
				"status":  "UNAUTHENTICATED",
			},
		})
	}))
	defer server.Close()

	provider := New(Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		CallbackURL:  "https://example.com/callback",
		UserInfoURL:  server.URL,
	})

	_, err := provider.UserInfo(context.Background(), &social.Token{AccessToken: "bad"})
	require.Error(t, err)

	var perr *social.ProviderError
	require.True(t, errors.As(err, &perr))
	assert.Equal(t, "google", perr.Provider)
	assert.Equal(t, "user_info", perr.Operation)
	assert.Equal(t, http.StatusUnauthorized, perr.Status)
	assert.Equal(t, "UNAUTHENTICATED", perr.Code)
}
