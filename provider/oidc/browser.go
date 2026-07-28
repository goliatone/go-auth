package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
)

type BrowserAuthenticator struct {
	providers              map[string]*Provider
	stateStore             StateStore
	tokenExchanger         TokenExchanger
	userInfoFetcher        UserInfoFetcher
	identityLinker         IdentityLinker
	tokenIssuer            BrowserTokenIssuer
	principalTokenIssuer   PrincipalTokenIssuer
	principalMapper        PrincipalMapper
	sessionHandoff         ProviderSessionHandoff
	sessionMode            BrowserSessionMode
	localClaimPolicy       LocalClaimPolicy
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
	if cfg.SessionMode == ProviderSessionMode || cfg.LocalClaimPolicy.Enabled() {
		for key, provider := range providers {
			if provider.Config.TokenEndpointAuthMethod == TokenEndpointAuthUnspecified {
				return nil, cloneWithProvider(ErrInvalidConfig, key, map[string]any{"field": "token_endpoint_auth_method"})
			}
			if _, err := resolveTokenEndpointAuthMethod(provider.Config, provider.Metadata); err != nil {
				return nil, err
			}
		}
	}

	return &BrowserAuthenticator{
		providers:              providers,
		stateStore:             deps.stateStore,
		tokenExchanger:         deps.tokenExchanger,
		userInfoFetcher:        deps.userInfoFetcher,
		identityLinker:         cfg.IdentityLinker,
		tokenIssuer:            cfg.TokenIssuer,
		principalTokenIssuer:   cfg.PrincipalTokenIssuer,
		principalMapper:        cfg.PrincipalMapper,
		sessionHandoff:         cfg.SessionHandoff,
		sessionMode:            cfg.SessionMode,
		localClaimPolicy:       cfg.LocalClaimPolicy,
		defaultRedirect:        deps.defaultRedirect,
		allowedRedirectOrigins: originSet(cfg.AllowedRedirectOrigins),
		clock:                  deps.clock,
		stateTTL:               deps.stateTTL,
	}, nil
}

//nolint:gocyclo // Optional dependency combinations are validated explicitly to preserve compatibility.
func browserAuthenticatorDependenciesFromConfig(cfg BrowserAuthenticatorConfig) (browserAuthenticatorDependencies, error) {
	if err := cfg.LocalClaimPolicy.validate(); err != nil {
		return browserAuthenticatorDependencies{}, err
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}

	stateStore := cfg.StateStore
	if stateStore == nil {
		stateStore = NewMemoryStateStoreWithCapacity(clock, cfg.StateCapacity)
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
	switch cfg.SessionMode {
	case LocalTokenMode:
		if cfg.LocalClaimPolicy.Enabled() {
			if cfg.PrincipalTokenIssuer == nil {
				return browserAuthenticatorDependencies{}, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "principal_token_issuer"})
			}
		} else if cfg.TokenIssuer == nil {
			return browserAuthenticatorDependencies{}, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "token_issuer"})
		}
	case ProviderSessionMode:
		if cfg.SessionHandoff == nil {
			return browserAuthenticatorDependencies{}, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "session_handoff"})
		}
		capability, ok := cfg.IdentityLinker.(IdentityLinkerSecurityCapability)
		if !ok || capability.IdentifierBindingMode() < IdentifierBindingImmutableRequired {
			return browserAuthenticatorDependencies{}, cloneWithProvider(ErrInvalidConfig, "", map[string]any{
				"field": "identity_linker", "cause": "provider session mode requires immutable identifier binding",
			})
		}
		if cfg.TokenIssuer != nil || cfg.PrincipalTokenIssuer != nil {
			return browserAuthenticatorDependencies{}, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "session_mode", "cause": "local issuer is incompatible with provider session mode"})
		}
	default:
		return browserAuthenticatorDependencies{}, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "session_mode"})
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
	if provider == nil {
		return cloneWithProvider(ErrInvalidConfig, key, map[string]any{"field": "provider"})
	}
	if err := provider.Config.validate(); err != nil {
		return err
	}
	if err := validateDiscoveryEndpoints(provider.Config, provider.Metadata); err != nil {
		return err
	}
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

type callbackAuthentication struct {
	external     ExternalIdentity
	validated    *ValidatedProviderIdentity
	mappedClaims *auth.JWTClaims
	tokenSet     auth.ProviderTokenSet
}

func (a *BrowserAuthenticator) BeginLogin(ctx context.Context, req AuthorizationRequest) (AuthorizationResponse, error) {
	provider, err := a.provider(req.ProviderKey)
	if err != nil {
		return AuthorizationResponse{}, err
	}
	limits := provider.Config.Limits.normalized()
	if len(req.ProviderKey) > limits.ProviderKeyBytes || len(req.RedirectTo) > limits.RedirectBytes {
		return AuthorizationResponse{}, cloneWithProvider(ErrInvalidState, req.ProviderKey, map[string]any{"cause": "begin-login input exceeds limit"})
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

	now := a.clock()
	expiresAt := now.Add(a.stateTTL)
	err = a.stateStore.Save(ctx, StateRecord{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		ProviderKey:  provider.Config.Key,
		RedirectTo:   redirectTo,
		CreatedAt:    now,
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
	if validationErr := validateCallbackRequestLimits(req, provider.Config.Limits.normalized(), provider.Config.Key); validationErr != nil {
		return BrowserSessionResult{}, validationErr
	}

	redirectTarget, err := a.callbackRedirectTarget(record, req)
	if err != nil {
		return BrowserSessionResult{}, err
	}

	callback, err := a.callbackIdentity(ctx, provider, record, req)
	if err != nil {
		return BrowserSessionResult{}, err
	}

	localIdentity, decision, err := a.resolveLocalIdentity(ctx, callback.external)
	if err != nil {
		return BrowserSessionResult{}, err
	}

	return a.buildSessionResult(ctx, provider, redirectTarget, callback, localIdentity, decision)
}

func (a *BrowserAuthenticator) consumeCallbackState(ctx context.Context, req CallbackRequest) (StateRecord, error) {
	limits := Limits{}.normalized()
	if a != nil {
		if provider, ok := a.providers[normalizeProviderKey(req.ProviderKey)]; ok && provider != nil {
			limits = provider.Config.Limits.normalized()
		}
	}
	if err := validateCallbackRequestLimits(req, limits, req.ProviderKey); err != nil {
		return StateRecord{}, err
	}
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

func validateCallbackRequestLimits(req CallbackRequest, limits Limits, providerKey string) error {
	if len(req.ProviderKey) > limits.ProviderKeyBytes ||
		len(req.Code) > limits.CallbackCodeBytes ||
		len(req.State) > limits.CallbackStateBytes ||
		len(req.RedirectTo) > limits.RedirectBytes {
		return cloneWithProvider(ErrInvalidState, providerKey, map[string]any{"cause": "callback input exceeds limit"})
	}
	return nil
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

//nolint:gocyclo,funlen // Callback validation gates stay sequential to preserve fail-closed token handling.
func (a *BrowserAuthenticator) callbackIdentity(ctx context.Context, provider *Provider, record StateRecord, req CallbackRequest) (callbackAuthentication, error) {
	tokenResponse, err := a.tokenExchanger.Exchange(ctx, provider.Config, provider.Metadata, req.Code, record.CodeVerifier)
	if err != nil {
		return callbackAuthentication{}, cloneWithProvider(ErrTokenExchangeFailed, provider.Config.Key, map[string]any{"cause": "provider operation failed"})
	}
	idToken, err := tokenResponse.idToken()
	if err != nil {
		return callbackAuthentication{}, err
	}
	accessToken, err := tokenResponse.accessToken()
	if err != nil {
		return callbackAuthentication{}, err
	}
	refreshToken, err := tokenResponse.refreshToken()
	if err != nil {
		return callbackAuthentication{}, err
	}
	tokenResponse.IDTokenValue = idToken
	tokenResponse.AccessTokenValue = accessToken
	tokenResponse.RefreshTokenValue = refreshToken
	tokenResponse.IDToken, tokenResponse.AccessToken, tokenResponse.RefreshToken = "", "", ""
	if idToken.IsZero() {
		return callbackAuthentication{}, cloneWithProvider(ErrInvalidIDToken, provider.Config.Key, map[string]any{"cause": "missing id_token"})
	}

	idClaims, err := provider.Validator.ValidateIDTokenWithAccessToken(ctx, idToken.Reveal(), record.Nonce, accessToken.Reveal())
	if err != nil {
		return callbackAuthentication{}, err
	}

	userInfo, err := a.fetchUserInfo(ctx, provider, tokenResponse)
	if err != nil {
		return callbackAuthentication{}, err
	}
	userInfo, err = correlatedProfileUserInfo(provider.Config.Key, idClaims, userInfo)
	if err != nil {
		return callbackAuthentication{}, err
	}

	if !a.hardenedFlow() {
		mapper := provider.Config.ClaimMapper
		if mapper == nil {
			mapper = DefaultClaimsMapper{}
		}
		identity, mappedClaims, mapErr := mapper.MapClaims(ctx, provider.Config, idClaims, userInfo)
		if mapErr != nil {
			return callbackAuthentication{}, mapErr
		}
		return callbackAuthentication{external: identity, mappedClaims: mappedClaims}, nil
	}

	idContext, err := validatedIDTokenContext(idClaims, provider.Config)
	if err != nil {
		return callbackAuthentication{}, err
	}
	var accessClaims jwt.MapClaims
	var accessContext *auth.ValidatedTokenContext
	if provider.Config.RequireAccessTokenClaims {
		if accessToken.IsZero() {
			return callbackAuthentication{}, cloneWithProvider(ErrInvalidIDToken, provider.Config.Key, map[string]any{"field": "access_token"})
		}
		accessClaims, err = provider.Validator.ValidateAccessToken(ctx, accessToken.Reveal())
		if err != nil {
			return callbackAuthentication{}, err
		}
		validatedAccess, contextErr := validatedTokenContext(accessClaims)
		if contextErr != nil {
			return callbackAuthentication{}, contextErr
		}
		accessContext = &validatedAccess
	}
	mapper := a.principalMapper
	if mapper == nil {
		mapper = DefaultPrincipalMapper{}
	}
	validated, err := mapper.MapPrincipal(ctx, provider.Config, idContext, accessContext, idClaims, accessClaims, userInfo)
	if err != nil {
		return callbackAuthentication{}, err
	}
	validated, err = validateMappedPrincipal(ctx, provider.Config, idContext, accessContext, idClaims, accessClaims, userInfo, validated)
	if err != nil {
		return callbackAuthentication{}, err
	}
	tokenSet, err := tokenSetFromResponse(tokenResponse, a.clock(), idContext, accessContext)
	if err != nil {
		return callbackAuthentication{}, err
	}
	return callbackAuthentication{
		external:  validated.externalIdentity(),
		validated: &validated,
		tokenSet:  tokenSet,
	}, nil
}

func (a *BrowserAuthenticator) hardenedFlow() bool {
	return a != nil && (a.sessionMode == ProviderSessionMode || a.localClaimPolicy.Enabled())
}

func tokenSetFromResponse(response TokenResponse, acquiredAt time.Time, idContext auth.ValidatedTokenContext, accessContext *auth.ValidatedTokenContext) (auth.ProviderTokenSet, error) {
	var accessExpiresAt time.Time
	var refreshExpiresAt time.Time
	if response.ExpiresIn > 0 {
		accessExpiresAt = acquiredAt.Add(time.Duration(response.ExpiresIn) * time.Second)
	}
	if accessContext != nil && !accessContext.ExpiresAt.IsZero() {
		accessExpiresAt = accessContext.ExpiresAt
	}
	if response.RefreshExpiresIn > 0 {
		refreshExpiresAt = acquiredAt.Add(time.Duration(response.RefreshExpiresIn) * time.Second)
	}
	return auth.NewProviderTokenSet(auth.ProviderTokenSetInput{
		AccessToken:      response.AccessTokenValue,
		RefreshToken:     response.RefreshTokenValue,
		IDToken:          response.IDTokenValue,
		TokenType:        response.TokenType,
		Scopes:           strings.Fields(response.Scope),
		AcquiredAt:       acquiredAt,
		AccessExpiresAt:  accessExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
		IDExpiresAt:      idContext.ExpiresAt,
		IDContext:        &idContext,
		AccessContext:    accessContext,
	})
}

func (v ValidatedProviderIdentity) externalIdentity() ExternalIdentity {
	return ExternalIdentity{
		Provider: v.Provider, Subject: v.Subject, Email: v.Email,
		EmailVerified: v.EmailVerified, Name: v.Name, GivenName: v.GivenName,
		FamilyName: v.FamilyName, Nickname: v.Nickname, Picture: v.Picture,
		TenantID: v.TenantID, OrganizationID: v.OrganizationID,
		ResourceRoles: v.ResourceRoles,
	}
}

func principalFromValidated(applicationSubject string, identity ValidatedProviderIdentity) (auth.AuthenticatedPrincipal, error) {
	return auth.NewAuthenticatedPrincipal(auth.AuthenticatedPrincipalInput{
		ApplicationSubject: applicationSubject,
		Provider:           identity.Provider,
		ProviderSubject:    identity.Subject,
		ProviderSessionID:  identity.ProviderSessionID,
		ClientID:           identity.ClientID,
		AssuranceLevel:     identity.AssuranceLevel,
		AssuranceMethods:   identity.AssuranceMethods,
		AuthenticationAt:   identity.AuthenticationAt,
		IssuedAt:           identity.IssuedAt,
		ExpiresAt:          identity.ExpiresAt,
		TokenID:            identity.TokenID,
		TenantID:           identity.TenantID,
		OrganizationID:     identity.OrganizationID,
		PermissionVersion:  identity.PermissionVersion,
		Metadata:           identity.Metadata,
	})
}

func (a *BrowserAuthenticator) resolveLocalIdentity(ctx context.Context, identity ExternalIdentity) (auth.Identity, LinkingDecision, error) {
	localIdentity, decision, err := a.identityLinker.Resolve(ctx, identity)
	if err != nil {
		return nil, decision, err
	}
	if localIdentity == nil {
		return nil, decision, auth.ErrIdentityNotFound
	}
	if _, err := auth.EnsureIdentityActive(localIdentity); err != nil {
		return nil, decision, err
	}
	return localIdentity, decision, nil
}

func (a *BrowserAuthenticator) buildSessionResult(ctx context.Context, provider *Provider, redirectTarget string, callback callbackAuthentication, localIdentity auth.Identity, decision LinkingDecision) (BrowserSessionResult, error) {
	result := BrowserSessionResult{
		Identity:       callback.external,
		Claims:         callback.mappedClaims,
		ProviderKey:    provider.Config.Key,
		RedirectTarget: redirectTarget,
		Audit: AuditMetadata{
			EventType: auth.ActivityEventSSOLoginSuccess,
			UserID:    localIdentity.ID(),
			Metadata: map[string]any{
				"provider":         provider.Config.Key,
				"subject":          callback.external.Subject,
				"linking_decision": decision.Action,
			},
		},
	}
	if !a.hardenedFlow() {
		resourceRoles := callback.external.ResourceRoles
		if len(resourceRoles) == 0 && callback.mappedClaims != nil {
			resourceRoles = callback.mappedClaims.Resources
		}
		localToken, err := a.tokenIssuer.Generate(localIdentity, resourceRoles)
		if err != nil {
			return BrowserSessionResult{}, err
		}
		result.LocalToken = localToken
		return result, nil
	}
	principal, err := principalFromValidated(localIdentity.ID(), *callback.validated)
	if err != nil {
		return BrowserSessionResult{}, err
	}
	result.Principal = principal
	if a.sessionMode == ProviderSessionMode {
		handoff, handoffErr := a.sessionHandoff.CreateProviderSession(ctx, principal, callback.tokenSet)
		if handoffErr != nil || handoff.HostSession().IsZero() || strings.TrimSpace(handoff.LocalSessionID()) == "" {
			return BrowserSessionResult{}, cloneWithProvider(ErrTokenExchangeFailed, provider.Config.Key, map[string]any{"cause": "provider session handoff failed"})
		}
		principal, err = principal.BindLocalSessionID(handoff.LocalSessionID())
		if err != nil {
			return BrowserSessionResult{}, cloneWithProvider(ErrTokenExchangeFailed, provider.Config.Key, map[string]any{"cause": "provider session handoff failed"})
		}
		result.Principal = principal
		result.HostSession = handoff.HostSession()
		return result, nil
	}
	normalizedClaims, err := PrincipalLocalClaims(principal, a.localClaimPolicy)
	if err != nil {
		return BrowserSessionResult{}, err
	}
	localToken, err := a.principalTokenIssuer.GeneratePrincipal(localIdentity, normalizedClaims)
	if err != nil {
		return BrowserSessionResult{}, err
	}
	result.LocalToken = localToken
	return result, nil
}

func (a *BrowserAuthenticator) fetchUserInfo(ctx context.Context, provider *Provider, tokenResponse TokenResponse) (map[string]any, error) {
	if provider == nil || !provider.Config.UserInfo {
		return nil, nil
	}
	if strings.TrimSpace(provider.Metadata.UserInfoEndpoint) == "" {
		return nil, cloneWithProvider(ErrUserInfoFailed, provider.Config.Key, map[string]any{"field": "userinfo_endpoint"})
	}
	accessToken, err := tokenResponse.accessToken()
	if err != nil {
		return nil, err
	}
	if accessToken.IsZero() {
		return nil, cloneWithProvider(ErrUserInfoFailed, provider.Config.Key, map[string]any{"field": "access_token"})
	}
	userInfo, err := a.userInfoFetcher.FetchUserInfo(ctx, provider.Config, provider.Metadata, accessToken.Reveal())
	if err != nil {
		return nil, cloneWithProvider(ErrUserInfoFailed, provider.Config.Key, map[string]any{"cause": "provider operation failed"})
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
	for k, v := range provider.Config.AdditionalAuthParam {
		if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			query.Set(k, v)
		}
	}
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
