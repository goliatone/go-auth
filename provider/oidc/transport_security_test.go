package oidc

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestProviderConfigRequiresHTTPSOrExplicitLoopback(t *testing.T) {
	base := ProviderConfig{
		Key:         "test",
		Issuer:      "https://issuer.example",
		ClientID:    "client",
		RedirectURL: "https://app.example/callback",
	}
	for name, mutate := range map[string]func(*ProviderConfig){
		"issuer": func(provider *ProviderConfig) {
			provider.Issuer = "http://issuer.example"
		},
		"discovery": func(provider *ProviderConfig) {
			provider.Issuer = ""
			provider.DiscoveryURL = "http://issuer.example/.well-known/openid-configuration"
		},
		"redirect": func(provider *ProviderConfig) {
			provider.RedirectURL = "http://app.example/callback"
		},
	} {
		t.Run(name, func(t *testing.T) {
			provider := base
			mutate(&provider)
			if err := provider.validate(); !errorHasTextCode(err, TextCodeOIDCInvalidConfig) {
				t.Fatalf("expected insecure endpoint rejection, got %v", err)
			}
		})
	}

	loopback := base
	loopback.Issuer = "http://127.0.0.1:54321"
	loopback.RedirectURL = "http://localhost:8080/callback"
	loopback.AllowInsecureHTTP = true
	if err := loopback.validate(); err != nil {
		t.Fatalf("explicit loopback HTTP should be allowed: %v", err)
	}

	nonLoopback := loopback
	nonLoopback.Issuer = "http://issuer.example"
	if err := nonLoopback.validate(); !errorHasTextCode(err, TextCodeOIDCInvalidConfig) {
		t.Fatalf("insecure opt-in accepted non-loopback host: %v", err)
	}
}

func TestAdditionalAuthorizationParamsCannotOverrideProtocolFields(t *testing.T) {
	for _, key := range []string{
		"client_id", "redirect_uri", "response_type", "scope", "state",
		"nonce", "code_challenge", "code_challenge_method",
	} {
		t.Run(key, func(t *testing.T) {
			provider := testProviderConfig("https://issuer.example/")
			provider.AdditionalAuthParam = map[string]string{key: "attacker-controlled"}
			if err := provider.validate(); !errorHasTextCode(err, TextCodeOIDCInvalidConfig) {
				t.Fatalf("expected reserved parameter rejection, got %v", err)
			}
		})
	}

	provider := &Provider{
		Config: testProviderConfig("https://issuer.example/"),
		Metadata: DiscoveryMetadata{
			AuthorizationEndpoint: "https://issuer.example/authorize",
		},
	}
	provider.Config.AdditionalAuthParam = map[string]string{"prompt": "login"}
	raw, err := authorizationURL(provider, "state", "nonce", "verifier", "")
	if err != nil {
		t.Fatal(err)
	}
	query, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if query.Query().Get("prompt") != "login" || query.Query().Get("client_id") != provider.Config.ClientID {
		t.Fatalf("authorization parameters were not composed safely: %s", raw)
	}
}

func TestTokenExchangeDoesNotFollowSecretBearingRedirect(t *testing.T) {
	var targetCalls int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		atomic.AddInt32(&targetCalls, 1)
		_, _ = io.ReadAll(request.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	_, err := (HTTPTokenExchanger{Client: origin.Client()}).Exchange(
		context.Background(),
		ProviderConfig{
			Key:                     "test",
			ClientID:                "client",
			ClientSecret:            "client-secret-canary",
			TokenEndpointAuthMethod: TokenEndpointAuthClientSecretPost,
			RedirectURL:             "https://app.example/callback",
			AllowInsecureHTTP:       true,
		},
		DiscoveryMetadata{
			TokenEndpoint:            origin.URL,
			TokenEndpointAuthMethods: []string{string(TokenEndpointAuthClientSecretPost)},
		},
		"authorization-code-canary",
		"pkce-verifier-canary",
	)
	if err == nil {
		t.Fatal("expected redirecting token endpoint to fail")
	}
	if got := atomic.LoadInt32(&targetCalls); got != 0 {
		t.Fatalf("redirect target received %d secret-bearing requests", got)
	}
}

func TestUserInfoDoesNotFollowBearerRedirect(t *testing.T) {
	var targetCalls int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&targetCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusPermanentRedirect)
	}))
	defer origin.Close()

	_, err := (HTTPUserInfoFetcher{Client: origin.Client()}).FetchUserInfo(
		context.Background(),
		ProviderConfig{Key: "test", AllowInsecureHTTP: true},
		DiscoveryMetadata{UserInfoEndpoint: origin.URL},
		"bearer-token-canary",
	)
	if err == nil {
		t.Fatal("expected redirecting UserInfo endpoint to fail")
	}
	if got := atomic.LoadInt32(&targetCalls); got != 0 {
		t.Fatalf("redirect target received %d bearer requests", got)
	}
}

func TestDiscoveryDoesNotFollowRedirect(t *testing.T) {
	var targetCalls int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&targetCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer origin.Close()

	_, err := Discover(context.Background(), ProviderConfig{
		Key:               "test",
		DiscoveryURL:      origin.URL,
		ClientID:          "client",
		RedirectURL:       "https://app.example/callback",
		AllowInsecureHTTP: true,
	}, origin.Client())
	if err == nil {
		t.Fatal("expected redirecting discovery endpoint to fail")
	}
	if got := atomic.LoadInt32(&targetCalls); got != 0 {
		t.Fatalf("redirect target received %d discovery requests", got)
	}
}

func TestJWKSDoesNotFollowRedirect(t *testing.T) {
	var targetCalls int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&targetCalls, 1)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	provider := testProviderConfig("https://issuer.example/")
	_, err := NewTokenValidator(context.Background(), provider, DiscoveryMetadata{
		Issuer: provider.Issuer, JWKSURI: origin.URL, Algorithms: []string{"RS256"},
	}, WithValidatorHTTPClient(origin.Client()))
	if err == nil {
		t.Fatal("expected redirecting JWKS endpoint to fail")
	}
	if got := atomic.LoadInt32(&targetCalls); got != 0 {
		t.Fatalf("redirect target received %d JWKS requests", got)
	}
}
