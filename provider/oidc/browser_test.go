package oidc

import (
	"context"
	"net/url"
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
	if !errorHasTextCode(err, TextCodeOIDCUnsafeRedirect) {
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
	if !errorHasTextCode(err, TextCodeOIDCInvalidConfig) {
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

func TestBrowserAuthenticatorRejectsInactiveIdentityBeforeIssuance(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	tests := map[auth.UserStatus]string{
		auth.UserStatusPending:   auth.TextCodeAccountPending,
		auth.UserStatusSuspended: auth.TextCodeAccountSuspended,
		auth.UserStatusDisabled:  auth.TextCodeAccountDisabled,
		auth.UserStatusArchived:  auth.TextCodeAccountArchived,
	}
	for status, textCode := range tests {
		t.Run(string(status), func(t *testing.T) {
			authenticator, signer := newBrowserTestAuthenticator(t, now, nil)
			issuerCalled := false
			authenticator.identityLinker = linkerFunc(func(_ context.Context, identity ExternalIdentity) (auth.Identity, LinkingDecision, error) {
				return testIdentity{id: "local-user", email: identity.Email, status: status}, LinkingDecision{Action: "existing"}, nil
			})
			authenticator.tokenIssuer = tokenIssuerFunc(func(auth.Identity, map[string]string) (string, error) {
				issuerCalled = true
				return "must-not-issue", nil
			})

			begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{ProviderKey: "test"})
			if err != nil {
				t.Fatal(err)
			}
			idToken := signer(jwt.MapClaims{
				"iss": "https://issuer.example/", "sub": "subject-1", "aud": "client",
				"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(), "nonce": begin.Nonce,
			})
			authenticator.tokenExchanger = TokenExchangerFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string, string) (TokenResponse, error) {
				return TokenResponse{IDToken: idToken}, nil
			})

			_, err = authenticator.CompleteCallback(context.Background(), CallbackRequest{
				ProviderKey: "test",
				Code:        "code",
				State:       begin.State,
			})
			if !errorHasTextCode(err, textCode) {
				t.Fatalf("expected lifecycle error %s, got %v", textCode, err)
			}
			if issuerCalled {
				t.Fatal("token issuer ran for an inactive identity")
			}
		})
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
		return map[string]any{"sub": "subject-1", "email": "userinfo@example.com", "email_verified": true}, nil
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

func TestBrowserAuthenticatorCorrelatesAndFiltersUserInfoBeforeCustomMapping(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)

	t.Run("subject mismatch fails before custom mapper", func(t *testing.T) {
		authenticator, signer := newBrowserTestAuthenticator(t, now, nil)
		provider := authenticator.providers["test"]
		provider.Config.UserInfo = true
		provider.Metadata.UserInfoEndpoint = "https://issuer.example/userinfo"
		mapperCalled := false
		provider.Config.ClaimMapper = ClaimsMapperFunc(func(context.Context, ProviderConfig, jwt.MapClaims, map[string]any) (ExternalIdentity, *auth.JWTClaims, error) {
			mapperCalled = true
			return ExternalIdentity{}, nil, nil
		})

		begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{ProviderKey: "test"})
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
		authenticator.userInfoFetcher = UserInfoFetcherFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string) (map[string]any, error) {
			return map[string]any{"sub": "subject-2", "email": "other@example.com"}, nil
		})

		_, err = authenticator.CompleteCallback(context.Background(), CallbackRequest{
			ProviderKey: "test",
			Code:        "code",
			State:       begin.State,
		})
		if !errorHasTextCode(err, TextCodeOIDCInvalidIDToken) {
			t.Fatalf("expected invalid ID token error, got %v", err)
		}
		if mapperCalled {
			t.Fatal("custom mapper ran before UserInfo subject correlation")
		}
	})

	t.Run("custom mapper receives profile-only claims", func(t *testing.T) {
		authenticator, signer := newBrowserTestAuthenticator(t, now, nil)
		provider := authenticator.providers["test"]
		provider.Config.UserInfo = true
		provider.Metadata.UserInfoEndpoint = "https://issuer.example/userinfo"
		provider.Config.ClaimMapper = ClaimsMapperFunc(func(_ context.Context, provider ProviderConfig, claims jwt.MapClaims, userInfo map[string]any) (ExternalIdentity, *auth.JWTClaims, error) {
			for _, forbidden := range []string{"tenant_id", "roles", "permissions", "groups", "resource_roles"} {
				if _, ok := userInfo[forbidden]; ok {
					t.Fatalf("custom mapper received forbidden UserInfo claim %q: %+v", forbidden, userInfo)
				}
			}
			return ExternalIdentity{
				Provider: provider.Key,
				Subject:  claims["sub"].(string),
				Email:    userInfo["email"].(string),
			}, nil, nil
		})

		begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{ProviderKey: "test"})
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
		authenticator.userInfoFetcher = UserInfoFetcherFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string) (map[string]any, error) {
			return map[string]any{
				"sub": "subject-1", "email": "profile@example.com",
				"tenant_id": "tenant", "roles": []any{"admin"},
				"permissions": []any{"admin:all"}, "groups": []any{"admin"},
				"resource_roles": map[string]any{"admin": "owner"},
			}, nil
		})

		result, err := authenticator.CompleteCallback(context.Background(), CallbackRequest{
			ProviderKey: "test",
			Code:        "code",
			State:       begin.State,
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Identity.Email != "profile@example.com" {
			t.Fatalf("profile enrichment failed: %+v", result.Identity)
		}
	})
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

func TestMemoryStateStoreSweepsExpiredEntriesAndFailsClosedAtCapacity(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	store := NewMemoryStateStoreWithCapacity(func() time.Time { return now }, 2)
	ctx := context.Background()

	for _, record := range []StateRecord{
		{State: "active-1", ExpiresAt: now.Add(time.Minute)},
		{State: "active-2", ExpiresAt: now.Add(time.Minute)},
	} {
		if err := store.Save(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Save(ctx, StateRecord{State: "active-1", ExpiresAt: now.Add(time.Minute)}); !errorHasTextCode(err, TextCodeOIDCInvalidState) {
		t.Fatalf("expected duplicate state rejection, got %v", err)
	}
	if err := store.Save(ctx, StateRecord{State: "overflow", ExpiresAt: now.Add(time.Minute)}); !errorHasTextCode(err, TextCodeOIDCInvalidState) {
		t.Fatalf("expected bounded store rejection, got %v", err)
	}

	now = now.Add(2 * time.Minute)
	if err := store.Save(ctx, StateRecord{State: "after-sweep", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("expired states should be swept before capacity check: %v", err)
	}
}

func TestBrowserAuthenticatorCallbackFailures(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)

	t.Run("missing code", func(t *testing.T) {
		authenticator, _ := newBrowserTestAuthenticator(t, now, nil)
		_, err := authenticator.CompleteCallback(context.Background(), CallbackRequest{ProviderKey: "test", State: "state"})
		if !errorHasTextCode(err, TextCodeOIDCInvalidState) {
			t.Fatalf("expected invalid state error, got %v", err)
		}
	})

	t.Run("invalid state", func(t *testing.T) {
		authenticator, _ := newBrowserTestAuthenticator(t, now, nil)
		_, err := authenticator.CompleteCallback(context.Background(), CallbackRequest{ProviderKey: "test", Code: "code", State: "missing"})
		if !errorHasTextCode(err, TextCodeOIDCInvalidState) {
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
		if !errorHasTextCode(err, TextCodeOIDCInvalidState) {
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
		if !errorHasTextCode(err, TextCodeOIDCInvalidNonce) {
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
		if !errorHasTextCode(err, TextCodeOIDCInvalidState) {
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
	id     string
	email  string
	status auth.UserStatus
}

func (i testIdentity) ID() string       { return i.id }
func (i testIdentity) Username() string { return i.email }
func (i testIdentity) Email() string    { return i.email }
func (i testIdentity) Role() string     { return string(auth.RoleMember) }
func (i testIdentity) Status() auth.UserStatus {
	if i.status == "" {
		return auth.UserStatusActive
	}
	return i.status
}
func (i testIdentity) Metadata() map[string]any { return nil }
