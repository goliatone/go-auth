package oidc

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
)

func TestBrowserAuthenticatorBeginLogin(t *testing.T) {
	authenticator, _ := newBrowserTestAuthenticator(t, time.Now(), nil)

	res, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{
		ProviderKey: "test",
		RedirectTo:  "/admin",
		LoginHint:   "person@example.com",
	})
	if err != nil {
		t.Fatalf("BeginLogin returned error: %v", err)
	}
	parsed, err := url.Parse(res.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("response_type") != "code" ||
		query.Get("client_id") != "client" ||
		query.Get("redirect_uri") != "https://app.example/callback" ||
		query.Get("state") == "" ||
		query.Get("nonce") == "" ||
		query.Get("code_challenge") == "" ||
		query.Get("code_challenge_method") != "S256" ||
		query.Get("login_hint") != "person@example.com" {
		t.Fatalf("authorization URL missing required OIDC parameters: %s", res.RedirectURL)
	}
}

func TestBrowserAuthenticatorRejectsUnsafeRedirects(t *testing.T) {
	authenticator, _ := newBrowserTestAuthenticator(t, time.Now(), nil)

	_, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{
		ProviderKey: "test",
		RedirectTo:  "https://evil.example/admin",
	})
	if err == nil || !strings.Contains(err.Error(), "redirect target") {
		t.Fatalf("expected unsafe redirect error, got %v", err)
	}
}

func TestBrowserAuthenticatorRejectsInvalidProviderSetup(t *testing.T) {
	_, err := NewBrowserAuthenticator(BrowserAuthenticatorConfig{
		Providers: []*Provider{{
			Config: testProviderConfig("https://issuer.example/"),
			Metadata: DiscoveryMetadata{
				Issuer:                "https://issuer.example/",
				AuthorizationEndpoint: "https://issuer.example/authorize",
				TokenEndpoint:         "https://issuer.example/oauth/token",
				JWKSURI:               "https://issuer.example/jwks",
			},
		}},
		IdentityLinker: linkerFunc(func(context.Context, ExternalIdentity) (auth.Identity, LinkingDecision, error) {
			return testIdentity{id: "local-user"}, LinkingDecision{}, nil
		}),
		TokenIssuer: tokenIssuerFunc(func(auth.Identity, map[string]string) (string, error) { return "local-token", nil }),
	})
	if err == nil || !strings.Contains(err.Error(), "oidc configuration is invalid") {
		t.Fatalf("expected invalid provider setup error, got %v", err)
	}
}

func TestBrowserAuthenticatorCompleteCallback(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	authenticator, signer := newBrowserTestAuthenticator(t, now, nil)

	begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{
		ProviderKey: "test",
		RedirectTo:  "/admin",
	})
	if err != nil {
		t.Fatal(err)
	}

	idToken := signer(jwt.MapClaims{
		"iss":            "https://issuer.example/",
		"sub":            "subject-1",
		"aud":            "client",
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Add(-time.Minute).Unix(),
		"nonce":          begin.Nonce,
		"email":          "person@example.com",
		"email_verified": true,
	})
	authenticator.tokenExchanger = TokenExchangerFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string, string) (TokenResponse, error) {
		return TokenResponse{IDToken: idToken}, nil
	})

	result, err := authenticator.CompleteCallback(context.Background(), CallbackRequest{
		ProviderKey: "test",
		Code:        "code",
		State:       begin.State,
	})
	if err != nil {
		t.Fatalf("CompleteCallback returned error: %v", err)
	}
	if result.LocalToken != "local-token" || result.RedirectTarget != "/admin" || result.Identity.Subject != "subject-1" {
		t.Fatalf("unexpected browser result: %+v", result)
	}
}

func TestBrowserAuthenticatorFetchesUserInfoWhenEnabled(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	authenticator, signer := newBrowserTestAuthenticator(t, now, nil)
	provider := authenticator.providers["test"]
	provider.Config.UserInfo = true
	provider.Metadata.UserInfoEndpoint = "https://issuer.example/userinfo"

	begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{ProviderKey: "test", RedirectTo: "/admin"})
	if err != nil {
		t.Fatal(err)
	}
	idToken := signer(jwt.MapClaims{
		"iss": "https://issuer.example/", "sub": "subject-1", "aud": "client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(), "nonce": begin.Nonce,
	})
	authenticator.tokenExchanger = TokenExchangerFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string, string) (TokenResponse, error) {
		return TokenResponse{IDToken: idToken, AccessToken: "access-token"}, nil
	})
	authenticator.userInfoFetcher = UserInfoFetcherFunc(func(_ context.Context, _ ProviderConfig, _ DiscoveryMetadata, accessToken string) (map[string]any, error) {
		if accessToken != "access-token" {
			t.Fatalf("access token = %q, want access-token", accessToken)
		}
		return map[string]any{"email": "userinfo@example.com", "email_verified": true}, nil
	})

	result, err := authenticator.CompleteCallback(context.Background(), CallbackRequest{
		ProviderKey: "test",
		Code:        "code",
		State:       begin.State,
	})
	if err != nil {
		t.Fatalf("CompleteCallback returned error: %v", err)
	}
	if result.Identity.Email != "userinfo@example.com" || !result.Identity.EmailVerified {
		t.Fatalf("userinfo was not used to enrich identity: %+v", result.Identity)
	}
}

func TestBrowserAuthenticatorUsesConfiguredStateTTL(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	authenticator, _ := newBrowserTestAuthenticatorWithTTL(t, now, nil, time.Minute)

	begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{ProviderKey: "test", RedirectTo: "/admin"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := begin.ExpiresAt, now.Add(time.Minute); !got.Equal(want) {
		t.Fatalf("state expiry = %v, want %v", got, want)
	}
}

func TestBrowserAuthenticatorCallbackFailures(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)

	t.Run("missing code", func(t *testing.T) {
		authenticator, _ := newBrowserTestAuthenticator(t, now, nil)
		_, err := authenticator.CompleteCallback(context.Background(), CallbackRequest{ProviderKey: "test", State: "state"})
		if err == nil || !strings.Contains(err.Error(), "state is invalid") {
			t.Fatalf("expected invalid state error, got %v", err)
		}
	})

	t.Run("invalid state", func(t *testing.T) {
		authenticator, _ := newBrowserTestAuthenticator(t, now, nil)
		_, err := authenticator.CompleteCallback(context.Background(), CallbackRequest{ProviderKey: "test", Code: "code", State: "missing"})
		if err == nil || !strings.Contains(err.Error(), "state is invalid") {
			t.Fatalf("expected invalid state error, got %v", err)
		}
	})

	t.Run("expired state", func(t *testing.T) {
		authenticator, _ := newBrowserTestAuthenticator(t, now, nil)
		err := authenticator.stateStore.Save(context.Background(), StateRecord{
			State:        "state",
			ProviderKey:  "test",
			CodeVerifier: "verifier",
			Nonce:        "nonce",
			RedirectTo:   "/admin",
			ExpiresAt:    now.Add(-time.Second),
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = authenticator.CompleteCallback(context.Background(), CallbackRequest{ProviderKey: "test", Code: "code", State: "state"})
		if err == nil || !strings.Contains(err.Error(), "state is invalid") {
			t.Fatalf("expected expired state error, got %v", err)
		}
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		authenticator, signer := newBrowserTestAuthenticator(t, now, nil)
		begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{ProviderKey: "test", RedirectTo: "/admin"})
		if err != nil {
			t.Fatal(err)
		}
		idToken := signer(jwt.MapClaims{
			"iss": "https://issuer.example/", "sub": "subject-1", "aud": "client",
			"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(), "nonce": "wrong",
		})
		authenticator.tokenExchanger = TokenExchangerFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string, string) (TokenResponse, error) {
			return TokenResponse{IDToken: idToken}, nil
		})
		_, err = authenticator.CompleteCallback(context.Background(), CallbackRequest{ProviderKey: "test", Code: "code", State: begin.State})
		if err == nil || !strings.Contains(err.Error(), "nonce is invalid") {
			t.Fatalf("expected nonce error, got %v", err)
		}
	})

	t.Run("callback redirect cannot override state redirect", func(t *testing.T) {
		exchanged := false
		authenticator, signer := newBrowserTestAuthenticator(t, now, nil)
		begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{ProviderKey: "test", RedirectTo: "/admin"})
		if err != nil {
			t.Fatal(err)
		}
		idToken := signer(jwt.MapClaims{
			"iss": "https://issuer.example/", "sub": "subject-1", "aud": "client",
			"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(), "nonce": begin.Nonce,
		})
		authenticator.tokenExchanger = TokenExchangerFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string, string) (TokenResponse, error) {
			exchanged = true
			return TokenResponse{IDToken: idToken}, nil
		})
		_, err = authenticator.CompleteCallback(context.Background(), CallbackRequest{
			ProviderKey: "test",
			Code:        "code",
			State:       begin.State,
			RedirectTo:  "/other",
		})
		if err == nil || !strings.Contains(err.Error(), "state is invalid") {
			t.Fatalf("expected state redirect mismatch error, got %v", err)
		}
		if exchanged {
			t.Fatal("token exchanger was called before rejecting callback redirect mismatch")
		}
	})
}

func newBrowserTestAuthenticator(t *testing.T, now time.Time, exchanger TokenExchanger) (*BrowserAuthenticator, func(jwt.MapClaims) string) {
	t.Helper()
	return newBrowserTestAuthenticatorWithTTL(t, now, exchanger, 0)
}

func newBrowserTestAuthenticatorWithTTL(t *testing.T, now time.Time, exchanger TokenExchanger, stateTTL time.Duration) (*BrowserAuthenticator, func(jwt.MapClaims) string) {
	t.Helper()
	key := mustRSAKey(t)
	validator := newTestValidator(t, "https://issuer.example/", []jwk{rsaJWK("kid-1", key.PublicKey, "RS256", "sig", nil)}, now)
	provider := &Provider{
		Config: testProviderConfig("https://issuer.example/"),
		Metadata: DiscoveryMetadata{
			Issuer:                "https://issuer.example/",
			AuthorizationEndpoint: "https://issuer.example/authorize",
			TokenEndpoint:         "https://issuer.example/oauth/token",
			JWKSURI:               "https://issuer.example/jwks",
			Algorithms:            []string{"RS256"},
		},
		Validator: validator,
	}
	if exchanger == nil {
		exchanger = TokenExchangerFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string, string) (TokenResponse, error) {
			return TokenResponse{}, ErrTokenExchangeFailed
		})
	}
	authenticator, err := NewBrowserAuthenticator(BrowserAuthenticatorConfig{
		Providers:      []*Provider{provider},
		StateStore:     NewMemoryStateStore(func() time.Time { return now }),
		TokenExchanger: exchanger,
		UserInfoFetcher: UserInfoFetcherFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string) (map[string]any, error) {
			return nil, nil
		}),
		IdentityLinker: linkerFunc(func(_ context.Context, identity ExternalIdentity) (auth.Identity, LinkingDecision, error) {
			return testIdentity{id: "local-user", email: identity.Email}, LinkingDecision{Action: "existing", UserID: "local-user"}, nil
		}),
		TokenIssuer:     tokenIssuerFunc(func(auth.Identity, map[string]string) (string, error) { return "local-token", nil }),
		DefaultRedirect: "/",
		Clock:           func() time.Time { return now },
		StateTTL:        stateTTL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authenticator, func(claims jwt.MapClaims) string {
		return signToken(t, key, "kid-1", claims)
	}
}

type linkerFunc func(context.Context, ExternalIdentity) (auth.Identity, LinkingDecision, error)

func (f linkerFunc) Resolve(ctx context.Context, identity ExternalIdentity) (auth.Identity, LinkingDecision, error) {
	return f(ctx, identity)
}

type tokenIssuerFunc func(auth.Identity, map[string]string) (string, error)

func (f tokenIssuerFunc) Generate(identity auth.Identity, resourceRoles map[string]string) (string, error) {
	return f(identity, resourceRoles)
}

type testIdentity struct {
	id    string
	email string
}

func (i testIdentity) ID() string               { return i.id }
func (i testIdentity) Username() string         { return i.email }
func (i testIdentity) Email() string            { return i.email }
func (i testIdentity) Role() string             { return string(auth.RoleMember) }
func (i testIdentity) Status() auth.UserStatus  { return auth.UserStatusActive }
func (i testIdentity) Metadata() map[string]any { return nil }
