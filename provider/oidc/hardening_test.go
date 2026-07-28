package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
)

func TestBrowserProviderSessionModeHandsOffSecretsAfterLinking(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	key := mustRSAKey(t)
	validator := newTestValidator(t, "https://issuer.example/", []jwk{rsaJWK("kid-1", key.PublicKey, "RS256", "sig", nil)}, now)
	providerConfig := testProviderConfig("https://issuer.example/")
	providerConfig.ClientSecretValue = auth.NewSecret("client-canary")
	providerConfig.TokenEndpointAuthMethod = TokenEndpointAuthClientSecretBasic
	provider := &Provider{
		Config: providerConfig,
		Metadata: DiscoveryMetadata{
			Issuer: "https://issuer.example/", AuthorizationEndpoint: "https://issuer.example/authorize",
			TokenEndpoint: "https://issuer.example/token", JWKSURI: "https://issuer.example/jwks",
			Algorithms: []string{"RS256"}, TokenEndpointAuthMethods: []string{"client_secret_basic"},
		},
		Validator: validator,
	}
	var idToken string
	var handedOff bool
	authenticator, err := NewBrowserAuthenticator(BrowserAuthenticatorConfig{
		Providers:  []*Provider{provider},
		StateStore: NewMemoryStateStore(func() time.Time { return now }),
		TokenExchanger: TokenExchangerFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string, string) (TokenResponse, error) {
			return TokenResponse{
				IDTokenValue: auth.NewSecret(idToken), AccessTokenValue: auth.NewSecret("access-canary"),
				RefreshTokenValue: auth.NewSecret("refresh-canary"), TokenType: "Bearer", ExpiresIn: 3600,
			}, nil
		}),
		IdentityLinker: capableLinker{IdentityLinker: linkerFunc(func(_ context.Context, identity ExternalIdentity) (auth.Identity, LinkingDecision, error) {
			return testIdentity{id: "local-user", email: identity.Email}, LinkingDecision{Action: "existing"}, nil
		})},
		SessionMode: ProviderSessionMode,
		SessionHandoff: ProviderSessionHandoffFunc(func(_ context.Context, principal auth.AuthenticatedPrincipal, tokens auth.ProviderTokenSet) (ProviderSessionHandoffResult, error) {
			handedOff = true
			if principal.ApplicationSubject() != "local-user" || principal.ProviderSubject() != "provider-user" {
				t.Fatalf("principal constructed before/without linking: %+v", principal)
			}
			if tokens.RefreshToken().Reveal() != "refresh-canary" {
				t.Fatal("provider token set did not reach handoff")
			}
			return NewProviderSessionHandoffResult(auth.NewSecret("host-session-canary"), "local-session")
		}),
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{ProviderKey: "test"})
	if err != nil {
		t.Fatal(err)
	}
	idToken = signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://issuer.example/", "sub": "provider-user", "aud": "client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(), "nonce": begin.Nonce,
		"sid": "provider-session", "acr": "aal2", "amr": []string{"pwd", "totp"},
	})
	result, err := authenticator.CompleteCallback(context.Background(), CallbackRequest{ProviderKey: "test", Code: "code", State: begin.State})
	if err != nil {
		t.Fatal(err)
	}
	if !handedOff || result.LocalToken != "" || result.HostSession.Reveal() != "host-session-canary" {
		t.Fatalf("unsafe or incomplete provider-session result: %+v", result)
	}
	if result.Principal.LocalSessionID() != "local-session" ||
		result.Principal.ProviderSessionID() != "provider-session" {
		t.Fatalf("session identifiers were not normalized: %+v", result.Principal)
	}
	if _, err := authenticator.CompleteCallback(context.Background(), CallbackRequest{ProviderKey: "test", Code: "code", State: begin.State}); err == nil {
		t.Fatal("consumed state was reusable")
	}
}

func TestBrowserProviderSessionModeRejectsLegacyMutableLinker(t *testing.T) {
	_, err := NewBrowserAuthenticator(BrowserAuthenticatorConfig{
		IdentityLinker: linkerFunc(func(context.Context, ExternalIdentity) (auth.Identity, LinkingDecision, error) {
			return testIdentity{id: "user"}, LinkingDecision{}, nil
		}),
		SessionMode: ProviderSessionMode,
		SessionHandoff: ProviderSessionHandoffFunc(func(context.Context, auth.AuthenticatedPrincipal, auth.ProviderTokenSet) (ProviderSessionHandoffResult, error) {
			return ProviderSessionHandoffResult{}, nil
		}),
	})
	if err == nil {
		t.Fatalf("expected immutable-linker construction failure, got %v", err)
	}
}

func TestBrowserModeDependencyMismatchesFailClosed(t *testing.T) {
	base := BrowserAuthenticatorConfig{IdentityLinker: linkerFunc(func(context.Context, ExternalIdentity) (auth.Identity, LinkingDecision, error) {
		return testIdentity{id: "user"}, LinkingDecision{}, nil
	})}
	tests := []struct {
		name   string
		mutate func(*BrowserAuthenticatorConfig)
	}{
		{"unknown mode", func(c *BrowserAuthenticatorConfig) { c.SessionMode = 99 }},
		{"provider handoff missing", func(c *BrowserAuthenticatorConfig) { c.SessionMode = ProviderSessionMode }},
		{"enriched issuer missing", func(c *BrowserAuthenticatorConfig) { c.LocalClaimPolicy.Allow = []LocalClaim{LocalClaimProvider} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := base
			test.mutate(&cfg)
			if _, err := NewBrowserAuthenticator(cfg); err == nil {
				t.Fatal("expected invalid configuration")
			}
		})
	}
}

type capableLinker struct {
	IdentityLinker
}

func (capableLinker) IdentifierBindingMode() IdentifierBindingMode {
	return IdentifierBindingImmutableRequired
}

func TestDefaultPrincipalMapperCorrelatesSources(t *testing.T) {
	idContext := auth.ValidatedTokenContext{
		Issuer: "https://issuer.example/", Subject: "subject-1", ClientID: "client",
		TenantID: "tenant-1", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	identity, err := (DefaultPrincipalMapper{}).MapPrincipal(context.Background(), ProviderConfig{Key: "test"}, idContext, nil,
		jwt.MapClaims{"sub": "subject-1", "email": "id@example.com"}, nil,
		map[string]any{"sub": "subject-1", "email": "userinfo@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if identity.Email != "userinfo@example.com" || identity.Provenance["email"] != ClaimSourceUserInfo {
		t.Fatalf("profile provenance mismatch: %+v", identity)
	}
	_, err = (DefaultPrincipalMapper{}).MapPrincipal(context.Background(), ProviderConfig{Key: "test"}, idContext, nil,
		jwt.MapClaims{"sub": "subject-1"}, nil, map[string]any{"sub": "other"})
	if err == nil {
		t.Fatal("expected UserInfo subject mismatch")
	}
	access := idContext
	access.Subject = "other"
	_, err = (DefaultPrincipalMapper{}).MapPrincipal(context.Background(), ProviderConfig{Key: "test"}, idContext, &access,
		jwt.MapClaims{"sub": "subject-1"}, nil, nil)
	if err == nil {
		t.Fatal("expected access-token subject mismatch")
	}
}

func TestCustomPrincipalMapperCannotForgeValidatedSecurityContext(t *testing.T) {
	idContext := auth.ValidatedTokenContext{
		Issuer: "https://issuer.example/", Subject: "subject-1", ClientID: "client",
		SessionID: "session-1", TenantID: "tenant-1", AssuranceLevel: "aal2",
		IssuedAt: time.Unix(100, 0), ExpiresAt: time.Unix(200, 0),
	}
	idClaims := jwt.MapClaims{"sub": "subject-1", "email": "person@example.com"}
	canonical, err := (DefaultPrincipalMapper{}).MapPrincipal(
		context.Background(), ProviderConfig{Key: "test", ClientID: "client"},
		idContext, nil, idClaims, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*ValidatedProviderIdentity){
		"subject": func(identity *ValidatedProviderIdentity) { identity.Subject = "attacker" },
		"client":  func(identity *ValidatedProviderIdentity) { identity.ClientID = "attacker-client" },
		"tenant":  func(identity *ValidatedProviderIdentity) { identity.TenantID = "attacker-tenant" },
		"expiry":  func(identity *ValidatedProviderIdentity) { identity.ExpiresAt = time.Unix(300, 0) },
		"roles": func(identity *ValidatedProviderIdentity) {
			identity.ResourceRoles = map[string]string{"admin": "owner"}
		},
		"metadata": func(identity *ValidatedProviderIdentity) {
			identity.Metadata = map[string]string{}
			for index := 0; index <= auth.DefaultPrincipalMetadataEntries; index++ {
				identity.Metadata[fmt.Sprintf("key-%d", index)] = "value"
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			mapped := canonical
			mutate(&mapped)
			_, err := validateMappedPrincipal(
				context.Background(),
				ProviderConfig{Key: "test", ClientID: "client"},
				idContext, nil, idClaims, nil, nil, mapped,
			)
			if !errorHasTextCode(err, TextCodeOIDCInvalidIDToken) {
				t.Fatalf("expected forged mapper output to fail, got %v", err)
			}
		})
	}
}

func TestForgedPrincipalMapperOutputFailsBeforeLinkingAndIssuance(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	authenticator, signer := newBrowserTestAuthenticator(t, now, nil)
	linkerCalled := false
	issuerCalled := false
	authenticator.localClaimPolicy = LocalClaimPolicy{Allow: []LocalClaim{LocalClaimProvider}}
	authenticator.principalMapper = PrincipalMapperFunc(func(
		context.Context,
		ProviderConfig,
		auth.ValidatedTokenContext,
		*auth.ValidatedTokenContext,
		jwt.MapClaims,
		jwt.MapClaims,
		map[string]any,
	) (ValidatedProviderIdentity, error) {
		return ValidatedProviderIdentity{Provider: "test", Subject: "attacker-subject"}, nil
	})
	authenticator.identityLinker = linkerFunc(func(context.Context, ExternalIdentity) (auth.Identity, LinkingDecision, error) {
		linkerCalled = true
		return testIdentity{id: "local-user"}, LinkingDecision{}, nil
	})
	authenticator.principalTokenIssuer = PrincipalTokenIssuerFunc(func(auth.Identity, map[string]any) (string, error) {
		issuerCalled = true
		return "must-not-issue", nil
	})

	begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{ProviderKey: "test"})
	if err != nil {
		t.Fatal(err)
	}
	idToken := signer(jwt.MapClaims{
		"iss": "https://issuer.example/", "sub": "trusted-subject", "aud": "client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(), "nonce": begin.Nonce,
	})
	authenticator.tokenExchanger = TokenExchangerFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string, string) (TokenResponse, error) {
		return TokenResponse{IDTokenValue: auth.NewSecret(idToken)}, nil
	})

	_, err = authenticator.CompleteCallback(context.Background(), CallbackRequest{
		ProviderKey: "test", Code: "code", State: begin.State,
	})
	if !errorHasTextCode(err, TextCodeOIDCInvalidIDToken) {
		t.Fatalf("expected forged mapper rejection, got %v", err)
	}
	if linkerCalled || issuerCalled {
		t.Fatalf("forged mapper crossed trust boundary: linker=%t issuer=%t", linkerCalled, issuerCalled)
	}
}

func TestPrincipalLocalClaimsUseOnlyExplicitAllowlist(t *testing.T) {
	principal, err := auth.NewAuthenticatedPrincipal(auth.AuthenticatedPrincipalInput{
		ApplicationSubject: "local-user", Provider: "test", ProviderSubject: "provider-user",
		AssuranceLevel: "aal2", PermissionVersion: "42",
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := PrincipalLocalClaims(principal, LocalClaimPolicy{Allow: []LocalClaim{
		LocalClaimProvider, LocalClaimAssuranceLevel,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 2 || claims["provider"] != "test" || claims["assurance_level"] != "aal2" {
		t.Fatalf("unexpected local claims: %v", claims)
	}
	if _, ok := claims["provider_subject"]; ok {
		t.Fatal("non-allowlisted claim was copied")
	}
	if _, err := PrincipalLocalClaims(principal, LocalClaimPolicy{Allow: []LocalClaim{"raw_tokens"}}); err == nil {
		t.Fatal("unknown local claim should fail closed")
	}
}

func TestValidatedIDTokenContextUsesValidatedClientBinding(t *testing.T) {
	context, err := validatedIDTokenContext(jwt.MapClaims{
		"iss":       "https://issuer.example/",
		"sub":       "provider-user",
		"azp":       "configured-client",
		"client_id": "different-client",
	}, ProviderConfig{ClientID: "configured-client"})
	if err != nil {
		t.Fatal(err)
	}
	if context.ClientID != "configured-client" {
		t.Fatalf("client ID = %q, want validated azp", context.ClientID)
	}

	context, err = validatedIDTokenContext(jwt.MapClaims{
		"iss":       "https://issuer.example/",
		"sub":       "provider-user",
		"client_id": "different-client",
	}, ProviderConfig{ClientID: "configured-client"})
	if err != nil {
		t.Fatal(err)
	}
	if context.ClientID != "configured-client" {
		t.Fatalf("client ID = %q, want configured client", context.ClientID)
	}
}

func TestEnrichedIssuerReceivesOnlyNormalizedAllowlistedClaims(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	base, signer := newBrowserTestAuthenticator(t, now, nil)
	provider := base.providers["test"]
	provider.Config.TokenEndpointAuthMethod = TokenEndpointAuthNone
	provider.Metadata.TokenEndpointAuthMethods = []string{string(TokenEndpointAuthNone)}

	var issuedClaims map[string]any
	authenticator, err := NewBrowserAuthenticator(BrowserAuthenticatorConfig{
		Providers:  []*Provider{provider},
		StateStore: NewMemoryStateStore(func() time.Time { return now }),
		TokenExchanger: TokenExchangerFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string, string) (TokenResponse, error) {
			return TokenResponse{}, ErrTokenExchangeFailed
		}),
		IdentityLinker: linkerFunc(func(_ context.Context, identity ExternalIdentity) (auth.Identity, LinkingDecision, error) {
			return testIdentity{id: "local-user", email: identity.Email}, LinkingDecision{Action: "existing"}, nil
		}),
		PrincipalTokenIssuer: PrincipalTokenIssuerFunc(func(_ auth.Identity, claims map[string]any) (string, error) {
			issuedClaims = claims
			return "enriched-local-token", nil
		}),
		LocalClaimPolicy: LocalClaimPolicy{Allow: []LocalClaim{
			LocalClaimProvider,
			LocalClaimProviderSessionID,
			LocalClaimAssuranceLevel,
		}},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{ProviderKey: "test"})
	if err != nil {
		t.Fatal(err)
	}
	idToken := signer(jwt.MapClaims{
		"iss": "https://issuer.example/", "sub": "provider-user", "aud": "client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(), "nonce": begin.Nonce,
		"sid": "provider-session", "acr": "aal2",
		"resource_roles": map[string]any{
			"admin": strings.Repeat("permission", 1024),
		},
	})
	authenticator.tokenExchanger = TokenExchangerFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string, string) (TokenResponse, error) {
		return TokenResponse{IDTokenValue: auth.NewSecret(idToken)}, nil
	})

	result, err := authenticator.CompleteCallback(context.Background(), CallbackRequest{
		ProviderKey: "test",
		Code:        "code",
		State:       begin.State,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.LocalToken != "enriched-local-token" {
		t.Fatalf("local token = %q", result.LocalToken)
	}
	if len(issuedClaims) != 3 ||
		issuedClaims[string(LocalClaimProvider)] != "test" ||
		issuedClaims[string(LocalClaimProviderSessionID)] != "provider-session" ||
		issuedClaims[string(LocalClaimAssuranceLevel)] != "aal2" {
		t.Fatalf("issuer received unexpected claims: %+v", issuedClaims)
	}
	if _, ok := issuedClaims["resource_roles"]; ok {
		t.Fatalf("resource roles crossed allowlist boundary: %+v", issuedClaims)
	}
}

func TestIDTokenBindingsValidateAZPAudienceAndAccessTokenHash(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	key := mustRSAKey(t)
	validator := newTestValidator(t, "https://issuer.example/", []jwk{rsaJWK("kid-1", key.PublicKey, "RS256", "sig", nil)}, now)
	accessToken := "opaque-access-canary"
	hash, err := accessTokenHash("RS256", accessToken)
	if err != nil {
		t.Fatal(err)
	}
	valid := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://issuer.example/", "sub": "user", "aud": "client", "azp": "client",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(), "at_hash": hash,
	})
	if _, err := validator.ValidateIDTokenWithAccessToken(context.Background(), valid, "", accessToken); err != nil {
		t.Fatal(err)
	}
	for name, claims := range map[string]jwt.MapClaims{
		"invalid azp":    {"iss": "https://issuer.example/", "sub": "user", "aud": "client", "azp": "other", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix()},
		"extra audience": {"iss": "https://issuer.example/", "sub": "user", "aud": []string{"client", "other"}, "azp": "client", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix()},
		"invalid hash":   {"iss": "https://issuer.example/", "sub": "user", "aud": "client", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "at_hash": "bad"},
	} {
		t.Run(name, func(t *testing.T) {
			raw := signToken(t, key, "kid-1", claims)
			if _, err := validator.ValidateIDTokenWithAccessToken(context.Background(), raw, "", accessToken); err == nil {
				t.Fatal("expected binding validation failure")
			}
		})
	}
}

func TestHTTPTokenExchangerAuthenticationMethods(t *testing.T) {
	for _, method := range []TokenEndpointAuthMethod{TokenEndpointAuthNone, TokenEndpointAuthClientSecretBasic, TokenEndpointAuthClientSecretPost} {
		t.Run(string(method), func(t *testing.T) {
			var gotForm url.Values
			var gotUser, gotPassword string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotUser, gotPassword, _ = r.BasicAuth()
				_ = r.ParseForm()
				gotForm = r.Form
				_, _ = w.Write([]byte(`{"access_token":"access","id_token":"id","token_type":"Bearer"}`))
			}))
			defer server.Close()
			provider := ProviderConfig{
				Key:                     "test",
				ClientID:                "client",
				RedirectURL:             "https://app.example/callback",
				TokenEndpointAuthMethod: method,
				AllowInsecureHTTP:       true,
			}
			if method != TokenEndpointAuthNone {
				provider.ClientSecretValue = auth.NewSecret("secret-canary")
			}
			_, err := (HTTPTokenExchanger{Client: server.Client()}).Exchange(context.Background(), provider,
				DiscoveryMetadata{TokenEndpoint: server.URL, TokenEndpointAuthMethods: []string{string(method)}}, "code", "verifier")
			if err != nil {
				t.Fatal(err)
			}
			switch method {
			case TokenEndpointAuthNone:
				if gotForm.Get("client_id") != "client" || gotForm.Get("client_secret") != "" {
					t.Fatalf("invalid public-client request: %v", gotForm)
				}
			case TokenEndpointAuthClientSecretBasic:
				if gotUser != "client" || gotPassword != "secret-canary" || gotForm.Get("client_secret") != "" {
					t.Fatalf("invalid basic request: user=%q form=%v", gotUser, gotForm)
				}
			case TokenEndpointAuthClientSecretPost:
				if gotForm.Get("client_secret") != "secret-canary" {
					t.Fatalf("invalid post request: %v", gotForm)
				}
			}
		})
	}
}

func TestTokenEndpointAuthDefaultsAndSecretMismatches(t *testing.T) {
	provider := ProviderConfig{Key: "test", ClientID: "client", TokenEndpointAuthMethod: TokenEndpointAuthClientSecretBasic}
	if _, err := resolveTokenEndpointAuthMethod(provider, DiscoveryMetadata{}); err == nil {
		t.Fatal("basic without secret should fail")
	}
	provider.ClientSecretValue = auth.NewSecret("canary")
	if method, err := resolveTokenEndpointAuthMethod(provider, DiscoveryMetadata{}); err != nil || method != TokenEndpointAuthClientSecretBasic {
		t.Fatalf("omitted metadata should default to Basic: %v %v", method, err)
	}
	provider.TokenEndpointAuthMethod = TokenEndpointAuthNone
	if _, err := resolveTokenEndpointAuthMethod(provider, DiscoveryMetadata{TokenEndpointAuthMethods: []string{"none"}}); err == nil {
		t.Fatal("none with secret should fail")
	}
	legacy := ProviderConfig{Key: "legacy", ClientID: "client"}
	if method, err := resolveTokenEndpointAuthMethod(legacy, DiscoveryMetadata{}); err != nil || method != TokenEndpointAuthNone {
		t.Fatalf("legacy public inference changed: %v %v", method, err)
	}
	legacy.ClientSecretValue = auth.NewSecret("canary")
	if method, err := resolveTokenEndpointAuthMethod(legacy, DiscoveryMetadata{}); err != nil || method != TokenEndpointAuthClientSecretPost {
		t.Fatalf("legacy confidential inference changed: %v %v", method, err)
	}
}

func TestTokenValidatorSupportsES256AndRejectsWrongCurve(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: []jwk{ecJWK("ec-1", key.PublicKey, "ES256", "P-256")}})
	}))
	defer server.Close()
	provider := testProviderConfig("https://issuer.example/")
	provider.AllowedAlgorithms = []string{"ES256"}
	validator, err := NewTokenValidator(context.Background(), provider, DiscoveryMetadata{
		Issuer: provider.Issuer, JWKSURI: server.URL, Algorithms: []string{"ES256"},
	}, WithValidatorHTTPClient(server.Client()), WithValidatorClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": provider.Issuer, "sub": "user", "aud": "api://default",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
	})
	token.Header["kid"] = "ec-1"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Validate(raw); err != nil {
		t.Fatal(err)
	}
	bad := ecJWK("bad", key.PublicKey, "ES256", "P-384")
	if _, err := bad.ecPublicKey(); err == nil {
		t.Fatal("expected unexpected curve rejection")
	}
}

func TestTokenValidatorAcceptsMixedRSAAndES256JWKS(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	rsaKey := mustRSAKey(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: []jwk{
			rsaJWK("rsa", rsaKey.PublicKey, "RS256", "sig", nil),
			ecJWK("ec", ecKey.PublicKey, "ES256", "P-256"),
		}})
	}))
	defer server.Close()
	provider := testProviderConfig("https://issuer.example/")
	provider.AllowedAlgorithms = []string{"RS256", "ES256"}
	validator, err := NewTokenValidator(context.Background(), provider, DiscoveryMetadata{
		Issuer: provider.Issuer, JWKSURI: server.URL, Algorithms: []string{"RS256", "ES256"},
	}, WithValidatorHTTPClient(server.Client()), WithValidatorClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{
		"iss": provider.Issuer, "sub": "user", "aud": "api://default",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
	}
	rsaRaw := signToken(t, rsaKey, "rsa", claims)
	ecToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	ecToken.Header["kid"] = "ec"
	ecRaw, err := ecToken.SignedString(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{rsaRaw, ecRaw} {
		if _, err := validator.Validate(raw); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBoundedJSONRejectsTrailingAndOversizedResponses(t *testing.T) {
	for name, body := range map[string]string{
		"trailing":  `{"issuer":"x"} {"extra":true}`,
		"oversized": strings.Repeat("x", 64),
	} {
		t.Run(name, func(t *testing.T) {
			var target map[string]any
			if err := decodeBoundedJSON(strings.NewReader(body), 32, &target); err == nil {
				t.Fatal("expected bounded JSON rejection")
			}
		})
	}
}

func TestOversizedCallbackInputIsRejectedBeforeStateConsumption(t *testing.T) {
	now := time.Now()
	authenticator, _ := newBrowserTestAuthenticator(t, now, nil)
	authenticator.providers["test"].Config.Limits.CallbackCodeBytes = 4
	begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{ProviderKey: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.CompleteCallback(context.Background(), CallbackRequest{
		ProviderKey: "test", Code: "oversized", State: begin.State,
	}); err == nil {
		t.Fatal("expected callback limit rejection")
	}
	if _, err := authenticator.stateStore.Consume(context.Background(), begin.State); err != nil {
		t.Fatalf("oversized callback consumed state: %v", err)
	}
}

func TestProviderCallbackLimitsAreRecheckedAfterStateResolution(t *testing.T) {
	now := time.Now()
	authenticator, _ := newBrowserTestAuthenticator(t, now, nil)
	authenticator.providers["test"].Config.Limits.CallbackCodeBytes = 4
	begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{ProviderKey: "test"})
	if err != nil {
		t.Fatal(err)
	}
	exchanged := false
	authenticator.tokenExchanger = TokenExchangerFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string, string) (TokenResponse, error) {
		exchanged = true
		return TokenResponse{}, nil
	})

	_, err = authenticator.CompleteCallback(context.Background(), CallbackRequest{
		Code:  "oversized",
		State: begin.State,
	})
	if !errorHasTextCode(err, TextCodeOIDCInvalidState) {
		t.Fatalf("expected provider limit rejection, got %v", err)
	}
	if exchanged {
		t.Fatal("token exchange ran before provider-specific callback limit validation")
	}
	if _, err := authenticator.stateStore.Consume(context.Background(), begin.State); err == nil {
		t.Fatal("post-consume limit failure restored callback state")
	}
}

func TestProviderRequestsAlwaysHaveEffectiveDeadline(t *testing.T) {
	var remaining time.Duration
	client := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Error("provider request had no deadline")
		} else {
			remaining = time.Until(deadline)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Header:     make(http.Header),
		}, nil
	})}
	fetcher := HTTPUserInfoFetcher{Client: client}
	_, _ = fetcher.FetchUserInfo(context.Background(), ProviderConfig{
		Key: "test", RequestTimeout: 250 * time.Millisecond,
	}, DiscoveryMetadata{UserInfoEndpoint: "https://issuer.example/userinfo"}, "access")
	if remaining <= 0 || remaining > 250*time.Millisecond {
		t.Fatalf("unexpected effective deadline: %s", remaining)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestOIDCResultFormattingAndJSONRedactSecrets(t *testing.T) {
	const canary = "callback-secret-canary"
	response := AuthorizationResponse{ProviderKey: "test", RedirectURL: "/redirect", State: canary, Nonce: canary, CodeVerifier: canary}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{string(encoded), fmt.Sprint(response), fmt.Sprintf("%+v", response), response.LogValue().String()} {
		if strings.Contains(output, canary) {
			t.Fatalf("authorization response leaked: %s", output)
		}
	}
	session := BrowserSessionResult{
		HostSession: auth.NewSecret(canary), ProviderKey: "test", RedirectTarget: "/admin",
	}
	encoded, err = json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), canary) || strings.Contains(fmt.Sprint(session), canary) {
		t.Fatal("browser session result leaked")
	}
	if _, err := json.Marshal(BrowserSessionResult{
		LocalToken: canary, HostSession: auth.NewSecret(canary),
		ProviderKey: "test", RedirectTarget: "/admin",
	}); err == nil {
		t.Fatal("ambiguous browser session result should fail closed")
	}
	handoff, err := NewProviderSessionHandoffResult(auth.NewSecret(canary), "local-session")
	if err != nil {
		t.Fatal(err)
	}
	if _, marshalErr := json.Marshal(handoff); marshalErr == nil {
		t.Fatal("provider session handoff JSON should fail closed")
	}
	if strings.Contains(fmt.Sprint(handoff), canary) {
		t.Fatal("provider session handoff formatting leaked")
	}
	legacyConfig := ProviderConfig{Key: "legacy", ClientSecret: canary}
	if output := fmt.Sprintf("%+v", legacyConfig); strings.Contains(output, canary) {
		t.Fatalf("legacy provider config formatting leaked: %s", output)
	}
	if _, marshalErr := json.Marshal(legacyConfig); marshalErr == nil {
		t.Fatal("provider config JSON should fail closed")
	}
	legacyTokens := TokenResponse{AccessToken: canary, IDToken: canary, RefreshToken: canary}
	if output := fmt.Sprintf("%+v", legacyTokens); strings.Contains(output, canary) {
		t.Fatalf("legacy token response formatting leaked: %s", output)
	}
	if _, marshalErr := json.Marshal(legacyTokens); marshalErr == nil {
		t.Fatal("token response JSON should fail closed")
	}
	callbackJSON, err := json.Marshal(CallbackRequest{ProviderKey: "test", Code: canary, State: canary})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(callbackJSON), canary) {
		t.Fatalf("callback JSON leaked: %s", callbackJSON)
	}
	if _, err := json.Marshal(StateRecord{State: canary, Nonce: canary, CodeVerifier: canary}); err == nil {
		t.Fatal("state record JSON should fail closed")
	}
}

func TestProviderSessionResultJSONIsStrictSafeView(t *testing.T) {
	canaries := []string{
		"email-canary@example.test",
		"name-canary",
		"subject-canary",
		"tenant-canary",
		"resource-role-canary",
		"metadata-token-canary",
		"cookie-secret-canary",
		"reason-canary",
		"correlation-canary",
		"principal-canary",
	}
	principal, err := auth.NewAuthenticatedPrincipal(auth.AuthenticatedPrincipalInput{
		ApplicationSubject: "principal-canary",
		Provider:           "test",
		ProviderSubject:    "subject-canary",
		ClientID:           "client",
		TenantID:           "tenant-canary",
	})
	if err != nil {
		t.Fatal(err)
	}
	result := BrowserSessionResult{
		HostSession: auth.NewSecret("cookie-secret-canary"),
		Principal:   principal,
		Identity: ExternalIdentity{
			Provider: "test", Subject: "subject-canary",
			Email: "email-canary@example.test", Name: "name-canary",
			TenantID:      "tenant-canary",
			ResourceRoles: map[string]string{"resource-role-canary": "role"},
			Metadata:      map[string]any{"token": "metadata-token-canary"},
		},
		Claims: &auth.JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{Subject: "subject-canary"},
		},
		ProviderKey:    "test",
		RedirectTarget: "/admin",
		Audit: AuditMetadata{
			EventType: auth.ActivityEventSSOLoginSuccess,
			UserID:    "principal-canary",
			Metadata: map[string]any{
				"provider":         "test",
				"subject":          "subject-canary",
				"linking_decision": LinkActionExisting,
				"reason":           "reason-canary",
				"correlation_id":   "correlation-canary",
			},
		},
	}

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	serialized := strings.ToLower(string(payload))
	for _, canary := range canaries {
		if strings.Contains(serialized, strings.ToLower(canary)) {
			t.Fatalf("provider-session JSON contains canary %q: %s", canary, serialized)
		}
	}
	for _, forbidden := range []string{
		"identity", "claims", "principal", "local_token", "host_session",
		"user_id", "subject", "reason", "metadata", "resource_roles",
	} {
		if strings.Contains(serialized, `"`+forbidden+`"`) {
			t.Fatalf("provider-session JSON contains forbidden field %q: %s", forbidden, serialized)
		}
	}
	if !strings.Contains(serialized, `"provider_key":"test"`) ||
		!strings.Contains(serialized, `"redirect_target":"/admin"`) ||
		!strings.Contains(serialized, `"linking_decision":"existing_subject"`) {
		t.Fatalf("provider-session JSON omitted safe view: %s", serialized)
	}
}

func TestCallbackWrapsProviderErrorsWithoutSecretDetails(t *testing.T) {
	const canary = "provider-error-secret-canary"
	now := time.Now()
	authenticator, _ := newBrowserTestAuthenticator(t, now, TokenExchangerFunc(func(context.Context, ProviderConfig, DiscoveryMetadata, string, string) (TokenResponse, error) {
		return TokenResponse{}, errors.New(canary)
	}))
	begin, err := authenticator.BeginLogin(context.Background(), AuthorizationRequest{ProviderKey: "test"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = authenticator.CompleteCallback(context.Background(), CallbackRequest{ProviderKey: "test", Code: canary, State: begin.State})
	if err == nil || strings.Contains(err.Error(), canary) {
		t.Fatalf("callback error leaked provider detail: %v", err)
	}
}

func ecJWK(kid string, key ecdsa.PublicKey, alg, curve string) jwk {
	encoded, err := key.Bytes()
	if err != nil {
		panic(err)
	}
	size := (len(encoded) - 1) / 2
	x := encoded[1 : 1+size]
	y := encoded[1+size:]
	return jwk{
		KeyID: kid, KeyType: "EC", Algorithm: alg, Use: "sig", Curve: curve,
		X: base64.RawURLEncoding.EncodeToString(x), Y: base64.RawURLEncoding.EncodeToString(y),
	}
}
