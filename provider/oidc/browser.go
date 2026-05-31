package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	auth "github.com/goliatone/go-auth"
)

type BrowserAuthenticator struct {
	providers              map[string]*Provider
	stateStore             StateStore
	tokenExchanger         TokenExchanger
	userInfoFetcher        UserInfoFetcher
	identityLinker         IdentityLinker
	tokenIssuer            BrowserTokenIssuer
	defaultRedirect        string
	allowedRedirectOrigins map[string]struct{}
	clock                  func() time.Time
	stateTTL               time.Duration
}

type browserAuthenticatorDependencies struct {
	stateStore      StateStore
	tokenExchanger  TokenExchanger
	userInfoFetcher UserInfoFetcher
	clock           func() time.Time
	defaultRedirect string
	stateTTL        time.Duration
}

func NewBrowserAuthenticator(cfg BrowserAuthenticatorConfig) (*BrowserAuthenticator, error) {
	deps, err := browserAuthenticatorDependenciesFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	providers, err := browserProviderMap(cfg.Providers)
	if err != nil {
		return nil, err
	}

	return &BrowserAuthenticator{
		providers:              providers,
		stateStore:             deps.stateStore,
		tokenExchanger:         deps.tokenExchanger,
		userInfoFetcher:        deps.userInfoFetcher,
		identityLinker:         cfg.IdentityLinker,
		tokenIssuer:            cfg.TokenIssuer,
		defaultRedirect:        deps.defaultRedirect,
		allowedRedirectOrigins: originSet(cfg.AllowedRedirectOrigins),
		clock:                  deps.clock,
		stateTTL:               deps.stateTTL,
	}, nil
}

func browserAuthenticatorDependenciesFromConfig(cfg BrowserAuthenticatorConfig) (browserAuthenticatorDependencies, error) {
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}

	stateStore := cfg.StateStore
	if stateStore == nil {
		stateStore = NewMemoryStateStore(clock)
	}

	tokenExchanger := cfg.TokenExchanger
	if tokenExchanger == nil {
		tokenExchanger = HTTPTokenExchanger{}
	}

	userInfoFetcher := cfg.UserInfoFetcher
	if userInfoFetcher == nil {
		userInfoFetcher = HTTPUserInfoFetcher{}
	}

	defaultRedirect := strings.TrimSpace(cfg.DefaultRedirect)
	if defaultRedirect == "" {
		defaultRedirect = "/"
	}
	if _, err := SafeRedirect(defaultRedirect, "/", cfg.AllowedRedirectOrigins); err != nil {
		return browserAuthenticatorDependencies{}, err
	}

	if cfg.IdentityLinker == nil {
		return browserAuthenticatorDependencies{}, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "identity_linker"})
	}
	if cfg.TokenIssuer == nil {
		return browserAuthenticatorDependencies{}, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "token_issuer"})
	}

	stateTTL := cfg.StateTTL
	if stateTTL <= 0 {
		stateTTL = 10 * time.Minute
	}

	return browserAuthenticatorDependencies{
		stateStore:      stateStore,
		tokenExchanger:  tokenExchanger,
		userInfoFetcher: userInfoFetcher,
		clock:           clock,
		defaultRedirect: defaultRedirect,
		stateTTL:        stateTTL,
	}, nil
}

func browserProviderMap(providerList []*Provider) (map[string]*Provider, error) {
	providers := make(map[string]*Provider, len(providerList))
	for _, provider := range providerList {
		if provider == nil {
			continue
		}
		key := normalizeProviderKey(provider.Config.Key)
		if key == "" {
			return nil, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "provider.key"})
		}
		if _, exists := providers[key]; exists {
			return nil, cloneWithProvider(ErrInvalidConfig, key, map[string]any{"field": "provider.key", "cause": "duplicate provider key"})
		}
		if err := validateBrowserProvider(key, provider); err != nil {
			return nil, err
		}
		providers[key] = provider
	}
	return providers, nil
}

func validateBrowserProvider(key string, provider *Provider) error {
	switch {
	case provider.Validator == nil:
		return cloneWithProvider(ErrInvalidConfig, key, map[string]any{"field": "provider.validator"})
	case strings.TrimSpace(provider.Metadata.Issuer) == "":
		return cloneWithProvider(ErrInvalidConfig, key, map[string]any{"field": "provider.metadata.issuer"})
	case strings.TrimSpace(provider.Metadata.AuthorizationEndpoint) == "":
		return cloneWithProvider(ErrInvalidConfig, key, map[string]any{"field": "provider.metadata.authorization_endpoint"})
	case strings.TrimSpace(provider.Metadata.TokenEndpoint) == "":
		return cloneWithProvider(ErrInvalidConfig, key, map[string]any{"field": "provider.metadata.token_endpoint"})
	case strings.TrimSpace(provider.Metadata.JWKSURI) == "":
		return cloneWithProvider(ErrInvalidConfig, key, map[string]any{"field": "provider.metadata.jwks_uri"})
	default:
		return nil
	}
}

func (a *BrowserAuthenticator) BeginLogin(ctx context.Context, req AuthorizationRequest) (AuthorizationResponse, error) {
	provider, err := a.provider(req.ProviderKey)
	if err != nil {
		return AuthorizationResponse{}, err
	}

	redirectTo, err := a.safeRedirect(req.RedirectTo)
	if err != nil {
		return AuthorizationResponse{}, err
	}

	state, err := randomURLValue(32)
	if err != nil {
		return AuthorizationResponse{}, err
	}
	nonce, err := randomURLValue(32)
	if err != nil {
		return AuthorizationResponse{}, err
	}
	verifier, err := randomURLValue(64)
	if err != nil {
		return AuthorizationResponse{}, err
	}

	expiresAt := a.clock().Add(a.stateTTL)
	err = a.stateStore.Save(ctx, StateRecord{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		ProviderKey:  provider.Config.Key,
		RedirectTo:   redirectTo,
		ExpiresAt:    expiresAt,
	})
	if err != nil {
		return AuthorizationResponse{}, err
	}

	authURL, err := authorizationURL(provider, state, nonce, verifier, req.LoginHint)
	if err != nil {
		return AuthorizationResponse{}, err
	}

	return AuthorizationResponse{
		ProviderKey:  provider.Config.Key,
		RedirectURL:  authURL,
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		ExpiresAt:    expiresAt,
	}, nil
}

func (a *BrowserAuthenticator) CompleteCallback(ctx context.Context, req CallbackRequest) (BrowserSessionResult, error) {
	record, err := a.consumeCallbackState(ctx, req)
	if err != nil {
		return BrowserSessionResult{}, err
	}

	provider, err := a.provider(record.ProviderKey)
	if err != nil {
		return BrowserSessionResult{}, err
	}

	redirectTarget, err := a.callbackRedirectTarget(record, req)
	if err != nil {
		return BrowserSessionResult{}, err
	}

	identity, mappedClaims, err := a.callbackIdentity(ctx, provider, record, req)
	if err != nil {
		return BrowserSessionResult{}, err
	}

	localIdentity, decision, err := a.resolveLocalIdentity(ctx, identity)
	if err != nil {
		return BrowserSessionResult{}, err
	}

	return a.buildSessionResult(provider, redirectTarget, identity, mappedClaims, localIdentity, decision)
}

func (a *BrowserAuthenticator) consumeCallbackState(ctx context.Context, req CallbackRequest) (StateRecord, error) {
	if strings.TrimSpace(req.Code) == "" {
		return StateRecord{}, cloneWithProvider(ErrInvalidState, req.ProviderKey, map[string]any{"field": "code"})
	}
	if strings.TrimSpace(req.State) == "" {
		return StateRecord{}, cloneWithProvider(ErrInvalidState, req.ProviderKey, map[string]any{"field": "state"})
	}

	record, err := a.stateStore.Consume(ctx, req.State)
	if err != nil {
		return StateRecord{}, err
	}
	if !record.ExpiresAt.IsZero() && !a.clock().Before(record.ExpiresAt) {
		return StateRecord{}, cloneWithProvider(ErrInvalidState, record.ProviderKey, map[string]any{"cause": "state expired"})
	}
	if req.ProviderKey != "" && normalizeProviderKey(req.ProviderKey) != normalizeProviderKey(record.ProviderKey) {
		return StateRecord{}, cloneWithProvider(ErrInvalidState, req.ProviderKey, map[string]any{"cause": "provider mismatch"})
	}
	return record, nil
}

func (a *BrowserAuthenticator) callbackRedirectTarget(record StateRecord, req CallbackRequest) (string, error) {
	if req.RedirectTo == "" {
		return record.RedirectTo, nil
	}
	callbackRedirect, err := a.safeRedirect(req.RedirectTo)
	if err != nil {
		return "", err
	}
	if callbackRedirect != record.RedirectTo {
		return "", cloneWithProvider(ErrInvalidState, record.ProviderKey, map[string]any{"cause": "redirect mismatch"})
	}
	return record.RedirectTo, nil
}

func (a *BrowserAuthenticator) callbackIdentity(ctx context.Context, provider *Provider, record StateRecord, req CallbackRequest) (ExternalIdentity, *auth.JWTClaims, error) {
	tokenResponse, err := a.tokenExchanger.Exchange(ctx, provider.Config, provider.Metadata, req.Code, record.CodeVerifier)
	if err != nil {
		return ExternalIdentity{}, nil, cloneWithProvider(ErrTokenExchangeFailed, provider.Config.Key, map[string]any{"cause": err.Error()})
	}
	if strings.TrimSpace(tokenResponse.IDToken) == "" {
		return ExternalIdentity{}, nil, cloneWithProvider(ErrInvalidIDToken, provider.Config.Key, map[string]any{"cause": "missing id_token"})
	}

	claims, err := provider.Validator.ValidateIDToken(ctx, tokenResponse.IDToken, record.Nonce)
	if err != nil {
		return ExternalIdentity{}, nil, err
	}

	userInfo, err := a.fetchUserInfo(ctx, provider, tokenResponse)
	if err != nil {
		return ExternalIdentity{}, nil, err
	}

	mapper := provider.Config.ClaimMapper
	if mapper == nil {
		mapper = DefaultClaimsMapper{}
	}
	identity, mappedClaims, err := mapper.MapClaims(ctx, provider.Config, claims, userInfo)
	if err != nil {
		return ExternalIdentity{}, nil, err
	}
	return identity, mappedClaims, nil
}

func (a *BrowserAuthenticator) resolveLocalIdentity(ctx context.Context, identity ExternalIdentity) (auth.Identity, LinkingDecision, error) {
	localIdentity, decision, err := a.identityLinker.Resolve(ctx, identity)
	if err != nil {
		return nil, decision, err
	}
	if localIdentity == nil {
		return nil, decision, auth.ErrIdentityNotFound
	}
	return localIdentity, decision, nil
}

func (a *BrowserAuthenticator) buildSessionResult(provider *Provider, redirectTarget string, identity ExternalIdentity, mappedClaims *auth.JWTClaims, localIdentity auth.Identity, decision LinkingDecision) (BrowserSessionResult, error) {
	resourceRoles := identity.ResourceRoles
	if len(resourceRoles) == 0 && mappedClaims != nil {
		resourceRoles = mappedClaims.Resources
	}
	localToken, err := a.tokenIssuer.Generate(localIdentity, resourceRoles)
	if err != nil {
		return BrowserSessionResult{}, err
	}

	return BrowserSessionResult{
		LocalToken:     localToken,
		Identity:       identity,
		Claims:         mappedClaims,
		ProviderKey:    provider.Config.Key,
		RedirectTarget: redirectTarget,
		Audit: AuditMetadata{
			EventType: auth.ActivityEventSSOLoginSuccess,
			UserID:    localIdentity.ID(),
			Metadata: map[string]any{
				"provider":         provider.Config.Key,
				"subject":          identity.Subject,
				"linking_decision": decision.Action,
			},
		},
	}, nil
}

func (a *BrowserAuthenticator) fetchUserInfo(ctx context.Context, provider *Provider, tokenResponse TokenResponse) (map[string]any, error) {
	if provider == nil || !provider.Config.UserInfo {
		return nil, nil
	}
	if strings.TrimSpace(provider.Metadata.UserInfoEndpoint) == "" {
		return nil, cloneWithProvider(ErrUserInfoFailed, provider.Config.Key, map[string]any{"field": "userinfo_endpoint"})
	}
	if strings.TrimSpace(tokenResponse.AccessToken) == "" {
		return nil, cloneWithProvider(ErrUserInfoFailed, provider.Config.Key, map[string]any{"field": "access_token"})
	}
	userInfo, err := a.userInfoFetcher.FetchUserInfo(ctx, provider.Config, provider.Metadata, tokenResponse.AccessToken)
	if err != nil {
		return nil, cloneWithProvider(ErrUserInfoFailed, provider.Config.Key, map[string]any{"cause": err.Error()})
	}
	return userInfo, nil
}

func (a *BrowserAuthenticator) provider(key string) (*Provider, error) {
	if a == nil {
		return nil, ErrInvalidConfig
	}
	provider, ok := a.providers[normalizeProviderKey(key)]
	if !ok {
		return nil, cloneWithProvider(ErrInvalidConfig, key, map[string]any{"field": "provider"})
	}
	return provider, nil
}

func (a *BrowserAuthenticator) safeRedirect(raw string) (string, error) {
	return SafeRedirect(raw, a.defaultRedirect, setToSlice(a.allowedRedirectOrigins))
}

func authorizationURL(provider *Provider, state string, nonce string, verifier string, loginHint string) (string, error) {
	endpoint := strings.TrimSpace(provider.Metadata.AuthorizationEndpoint)
	if endpoint == "" {
		return "", cloneWithProvider(ErrDiscoveryFailed, provider.Config.Key, map[string]any{"field": "authorization_endpoint"})
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", cloneWithProvider(ErrDiscoveryFailed, provider.Config.Key, map[string]any{"field": "authorization_endpoint"})
	}

	query := parsed.Query()
	query.Set("response_type", DefaultResponseType)
	query.Set("client_id", provider.Config.ClientID)
	query.Set("redirect_uri", provider.Config.RedirectURL)
	query.Set("scope", strings.Join(provider.Config.normalizedScopes(), " "))
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", codeChallenge(verifier))
	query.Set("code_challenge_method", "S256")
	if loginHint = strings.TrimSpace(loginHint); loginHint != "" {
		query.Set("login_hint", loginHint)
	}
	for k, v := range provider.Config.AdditionalAuthParam {
		if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			query.Set(k, v)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomURLValue(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func originSet(origins []string) map[string]struct{} {
	out := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		origin = strings.TrimRight(strings.TrimSpace(origin), "/")
		if origin != "" {
			out[origin] = struct{}{}
		}
	}
	return out
}

func setToSlice(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for origin := range set {
		out = append(out, origin)
	}
	return out
}
