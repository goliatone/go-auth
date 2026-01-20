package social

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/goliatone/go-auth"
)

// SocialAuthenticator orchestrates social login flows.
type SocialAuthenticator struct {
	providers       map[string]SocialProvider
	stateManager    StateManager
	linkingStrategy LinkingStrategy
	accountRepo     SocialAccountRepository
	userRepo        auth.Users
	roleProvider    auth.ResourceRoleProvider
	tokenService    auth.TokenService
	activitySink    auth.ActivitySink
	config          SocialAuthConfig
}

// SocialAuthConfig configures the social authenticator.
type SocialAuthConfig struct {
	BaseURL              string
	CallbackPath         string
	DefaultRedirectURL   string
	StateEncryptionKey   []byte
	StateHMACKey         []byte
	StateTTL             time.Duration
	AllowSignup          bool
	AllowLinking         bool
	RequireEmailVerified bool
	DefaultRole          string
}

// SocialAuthOption configures the social authenticator.
type SocialAuthOption func(*SocialAuthenticator)

// NewSocialAuthenticator creates a new social authenticator.
func NewSocialAuthenticator(
	accountRepo SocialAccountRepository,
	userRepo auth.Users,
	tokenService auth.TokenService,
	config SocialAuthConfig,
	opts ...SocialAuthOption,
) *SocialAuthenticator {
	cfg := config
	if cfg.StateTTL == 0 {
		cfg.StateTTL = 10 * time.Minute
	}

	sa := &SocialAuthenticator{
		providers:    make(map[string]SocialProvider),
		accountRepo:  accountRepo,
		userRepo:     userRepo,
		tokenService: tokenService,
		config:       cfg,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(sa)
		}
	}

	if sa.stateManager == nil {
		sa.stateManager = NewEncryptedStateManager(
			cfg.StateEncryptionKey,
			cfg.StateHMACKey,
			cfg.StateTTL,
		)
	}

	if sa.linkingStrategy == nil {
		sa.linkingStrategy = &DefaultLinkingStrategy{
			AllowSignup:          cfg.AllowSignup,
			AllowLinking:         cfg.AllowLinking,
			RequireEmailVerified: cfg.RequireEmailVerified,
			DefaultRole:          cfg.DefaultRole,
		}
	}

	return sa
}

// WithProvider registers a social provider.
func WithProvider(provider SocialProvider) SocialAuthOption {
	return func(sa *SocialAuthenticator) {
		if provider == nil {
			return
		}
		sa.providers[provider.Name()] = provider
	}
}

// WithStateManager sets a custom state manager.
func WithStateManager(sm StateManager) SocialAuthOption {
	return func(sa *SocialAuthenticator) {
		sa.stateManager = sm
	}
}

// WithLinkingStrategy sets a custom user linking strategy.
func WithLinkingStrategy(ls LinkingStrategy) SocialAuthOption {
	return func(sa *SocialAuthenticator) {
		sa.linkingStrategy = ls
	}
}

// WithLinkingPolicy sets a policy function used by the default resolver.
func WithLinkingPolicy(policy LinkingPolicy) SocialAuthOption {
	return func(sa *SocialAuthenticator) {
		sa.linkingStrategy = &PolicyLinkingStrategy{Policy: policy}
	}
}

// WithResourceRoleProvider sets the resource role provider used to enrich JWTs.
func WithResourceRoleProvider(rp auth.ResourceRoleProvider) SocialAuthOption {
	return func(sa *SocialAuthenticator) {
		sa.roleProvider = rp
	}
}

// WithActivitySink sets the activity sink for audit logging.
func WithActivitySink(sink auth.ActivitySink) SocialAuthOption {
	return func(sa *SocialAuthenticator) {
		sa.activitySink = sink
	}
}

// BeginAuth starts the OAuth flow for a provider.
func (sa *SocialAuthenticator) BeginAuth(
	ctx context.Context,
	providerName string,
	opts ...BeginAuthOption,
) (*AuthRedirect, error) {
	provider, ok := sa.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotFound, providerName)
	}

	if sa.stateManager == nil {
		return nil, ErrInvalidState
	}

	cfg := &beginAuthConfig{
		action:      ActionLogin,
		redirectURL: sa.config.DefaultRedirectURL,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}

	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}
	codeChallenge := computeCodeChallenge(codeVerifier)

	state := &OAuthState{
		Nonce:        generateNonce(),
		Provider:     providerName,
		CodeVerifier: codeVerifier,
		RedirectURL:  cfg.redirectURL,
		Action:       cfg.action,
		LinkUserID:   cfg.linkUserID,
		IssuedAt:     time.Now().Unix(),
		ExpiresAt:    time.Now().Add(sa.config.StateTTL).Unix(),
	}

	stateToken, err := sa.stateManager.Encode(state)
	if err != nil {
		return nil, fmt.Errorf("failed to encode state: %w", err)
	}

	authURL := provider.AuthCodeURL(stateToken, WithPKCE(codeChallenge, "S256"))

	return &AuthRedirect{
		URL:      authURL,
		State:    stateToken,
		Provider: providerName,
	}, nil
}

// CompleteAuth finishes the OAuth flow after callback.
func (sa *SocialAuthenticator) CompleteAuth(
	ctx context.Context,
	providerName string,
	code string,
	stateToken string,
) (*AuthResult, error) {
	if sa.stateManager == nil {
		return nil, ErrInvalidState
	}

	state, err := sa.stateManager.Decode(stateToken)
	if err != nil {
		if errors.Is(err, ErrStateExpired) {
			return nil, ErrStateExpired
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}

	if state.Provider != providerName {
		return nil, fmt.Errorf("%w: provider mismatch", ErrInvalidState)
	}

	if time.Now().Unix() > state.ExpiresAt {
		return nil, ErrStateExpired
	}

	provider, ok := sa.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotFound, providerName)
	}

	token, err := provider.Exchange(ctx, code, WithCodeVerifier(state.CodeVerifier))
	if err != nil {
		return nil, wrapProviderError(ErrTokenExchangeFailed, providerName, "exchange", err)
	}

	profile, err := provider.UserInfo(ctx, token)
	if err != nil {
		return nil, wrapProviderError(ErrUserInfoFailed, providerName, "user_info", err)
	}

	if sa.linkingStrategy == nil {
		return nil, ErrLinkingNotAllowed
	}

	result, err := sa.linkingStrategy.ResolveUser(ctx, LinkingContext{
		Profile:     profile,
		Action:      state.Action,
		LinkUserID:  state.LinkUserID,
		AccountRepo: sa.accountRepo,
		UserRepo:    sa.userRepo,
	})
	if err != nil {
		return nil, err
	}
	if result == nil || result.User == nil {
		return nil, auth.ErrIdentityNotFound
	}

	identity := auth.NewIdentityFromUser(result.User)
	if identity == nil {
		return nil, auth.ErrIdentityNotFound
	}

	if err := ensureIdentityActive(identity); err != nil {
		return nil, err
	}

	var expiresAt *time.Time
	if token != nil && !token.ExpiresAt.IsZero() {
		expiresAt = &token.ExpiresAt
	}
	account := &SocialAccount{
		UserID:         result.User.ID.String(),
		Provider:       providerName,
		ProviderUserID: profile.ProviderUserID,
		Email:          profile.Email,
		Name:           profile.Name,
		Username:       profile.Username,
		AvatarURL:      profile.AvatarURL,
	}
	if token != nil {
		account.AccessToken = token.AccessToken
		account.RefreshToken = token.RefreshToken
		account.TokenExpiresAt = expiresAt
		account.ProfileData = profile.Raw
	}

	if sa.accountRepo == nil {
		return nil, ErrLinkingNotAllowed
	}
	if err := sa.accountRepo.Upsert(ctx, account); err != nil {
		return nil, fmt.Errorf("failed to save social account: %w", err)
	}

	resourceRoles := map[string]string{}
	if sa.roleProvider != nil {
		roles, err := sa.roleProvider.FindResourceRoles(ctx, identity)
		if err != nil {
			return nil, err
		}
		resourceRoles = roles
	}

	jwtToken, err := sa.tokenService.Generate(identity, resourceRoles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	if sa.activitySink != nil {
		_ = sa.activitySink.Record(ctx, auth.ActivityEvent{
			EventType:  auth.ActivityEventSocialLogin,
			UserID:     identity.ID(),
			Actor:      auth.ActorRef{Type: "social", ID: providerName},
			OccurredAt: time.Now(),
			Metadata: map[string]any{
				"provider":         providerName,
				"provider_user_id": profile.ProviderUserID,
				"action":           state.Action,
				"is_new_user":      result.IsNewUser,
			},
		})
	}

	return &AuthResult{
		User:        identity,
		Token:       jwtToken,
		IsNewUser:   result.IsNewUser,
		Provider:    providerName,
		Profile:     profile,
		RedirectURL: state.RedirectURL,
	}, nil
}

// ListProviders returns all registered providers.
func (sa *SocialAuthenticator) ListProviders() []ProviderInfo {
	var providers []ProviderInfo
	for name, p := range sa.providers {
		providers = append(providers, ProviderInfo{
			Name:    name,
			AuthURL: p.AuthCodeURL(""),
		})
	}
	return providers
}

// ProviderInfo describes an available provider.
type ProviderInfo struct {
	Name    string
	AuthURL string
}

// AuthRedirect contains the authorization URL for redirecting users.
type AuthRedirect struct {
	URL      string
	State    string
	Provider string
}

// AuthResult contains the result of a successful authentication.
type AuthResult struct {
	User        auth.Identity
	Token       string
	IsNewUser   bool
	Provider    string
	Profile     *SocialProfile
	RedirectURL string
}

// BeginAuthOption configures the auth initiation.
type BeginAuthOption func(*beginAuthConfig)

type beginAuthConfig struct {
	action      string
	redirectURL string
	linkUserID  string
}

// ForAction sets the auth action (login, signup, link).
func ForAction(action string) BeginAuthOption {
	return func(c *beginAuthConfig) {
		c.action = action
	}
}

// WithRedirectURL sets the post-auth redirect URL.
func WithRedirectURL(url string) BeginAuthOption {
	return func(c *beginAuthConfig) {
		c.redirectURL = url
	}
}

// ForLinkingUser sets the user ID for account linking.
func ForLinkingUser(userID string) BeginAuthOption {
	return func(c *beginAuthConfig) {
		c.linkUserID = userID
		c.action = ActionLink
	}
}

// Actions.
const (
	ActionLogin  = "login"
	ActionSignup = "signup"
	ActionLink   = "link"
)

type statusAwareIdentity interface {
	Status() auth.UserStatus
}

func ensureIdentityActive(identity auth.Identity) error {
	if identity == nil {
		return auth.ErrIdentityNotFound
	}

	sa, ok := identity.(statusAwareIdentity)
	if !ok {
		return nil
	}

	status := sa.Status()
	if status == "" {
		status = auth.UserStatusActive
	}

	switch status {
	case auth.UserStatusSuspended:
		return auth.ErrUserSuspended
	case auth.UserStatusDisabled:
		return auth.ErrUserDisabled
	case auth.UserStatusArchived:
		return auth.ErrUserArchived
	case auth.UserStatusPending:
		return auth.ErrUserPending
	default:
		return nil
	}
}
