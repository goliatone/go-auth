package social

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-router"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type stubStateManager struct {
	states    map[string]*OAuthState
	lastToken string
	lastState *OAuthState
	seq       int
}

func (s *stubStateManager) Encode(state *OAuthState) (string, error) {
	if state == nil {
		return "", ErrInvalidState
	}
	if s.states == nil {
		s.states = map[string]*OAuthState{}
	}
	s.seq++
	token := fmt.Sprintf("state-%d", s.seq)
	s.states[token] = state
	s.lastToken = token
	s.lastState = state
	return token, nil
}

func (s *stubStateManager) Decode(token string) (*OAuthState, error) {
	if s.states == nil {
		return nil, ErrInvalidState
	}
	state, ok := s.states[token]
	if !ok {
		return nil, ErrInvalidState
	}
	return state, nil
}

type stubProvider struct {
	name        string
	authBase    string
	token       *Token
	profile     *SocialProfile
	exchangeErr error
	userInfoErr error
	lastState   string
}

func (p *stubProvider) Name() string {
	return p.name
}

func (p *stubProvider) AuthCodeURL(state string, opts ...AuthCodeOption) string {
	p.lastState = state
	return p.authBase + "?state=" + url.QueryEscape(state)
}

func (p *stubProvider) Exchange(ctx context.Context, code string, opts ...ExchangeOption) (*Token, error) {
	if p.exchangeErr != nil {
		return nil, p.exchangeErr
	}
	return p.token, nil
}

func (p *stubProvider) UserInfo(ctx context.Context, token *Token) (*SocialProfile, error) {
	if p.userInfoErr != nil {
		return nil, p.userInfoErr
	}
	return p.profile, nil
}

func (p *stubProvider) ValidateToken(ctx context.Context, token *Token) error {
	return nil
}

func (p *stubProvider) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	return nil, nil
}

type stubTokenService struct {
	token string
}

func (s stubTokenService) Generate(identity auth.Identity, resourceRoles map[string]string) (string, error) {
	return s.token, nil
}

func (s stubTokenService) SignClaims(claims *auth.JWTClaims) (string, error) {
	return s.token, nil
}

func (s stubTokenService) Validate(tokenString string) (auth.AuthClaims, error) {
	return &auth.JWTClaims{UID: "user", UserRole: string(auth.RoleMember)}, nil
}

type stubLinkingStrategy struct {
	result *LinkingResult
	err    error
}

func (s *stubLinkingStrategy) ResolveUser(ctx context.Context, lc LinkingContext) (*LinkingResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

type stubAccountRepo struct {
	byUser      map[string][]*SocialAccount
	upserts     []*SocialAccount
	deleteCalls []string
}

func (s *stubAccountRepo) FindByProviderID(ctx context.Context, provider, providerUserID string) (*SocialAccount, error) {
	for _, accounts := range s.byUser {
		for _, account := range accounts {
			if account.Provider == provider && account.ProviderUserID == providerUserID {
				return account, nil
			}
		}
	}
	return nil, errors.New("not found")
}

func (s *stubAccountRepo) FindByUserID(ctx context.Context, userID string) ([]*SocialAccount, error) {
	if s.byUser == nil {
		return nil, nil
	}
	return s.byUser[userID], nil
}

func (s *stubAccountRepo) Upsert(ctx context.Context, account *SocialAccount) error {
	s.upserts = append(s.upserts, account)
	if s.byUser == nil {
		s.byUser = map[string][]*SocialAccount{}
	}
	s.byUser[account.UserID] = append(s.byUser[account.UserID], account)
	return nil
}

func (s *stubAccountRepo) Delete(ctx context.Context, id string) error {
	s.deleteCalls = append(s.deleteCalls, id)
	return nil
}

func (s *stubAccountRepo) DeleteByUserAndProvider(ctx context.Context, userID, provider string) error {
	s.deleteCalls = append(s.deleteCalls, userID+"|"+provider)
	return nil
}

func TestHTTPControllerBeginAuthRedirects(t *testing.T) {
	stateManager := &stubStateManager{}
	provider := &stubProvider{
		name:     "github",
		authBase: "https://auth.example/authorize",
	}

	authenticator := NewSocialAuthenticator(nil, nil, nil, SocialAuthConfig{},
		WithStateManager(stateManager),
		WithProvider(provider),
	)

	controller := NewHTTPController(authenticator, HTTPConfig{
		SuccessRedirect: "/fallback",
	})

	ctx := router.NewMockContext()
	ctx.ParamsM["provider"] = "github"
	ctx.QueriesM["redirect_url"] = "/after"
	ctx.On("Context").Return(context.Background())

	var redirectURL string
	ctx.On("Redirect", mock.Anything, []int{http.StatusTemporaryRedirect}).Run(func(args mock.Arguments) {
		redirectURL = args.String(0)
	}).Return(nil)

	err := controller.BeginAuth(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, redirectURL)
	require.Equal(t, stateManager.lastToken, provider.lastState)
	require.Equal(t, "/after", stateManager.lastState.RedirectURL)
	require.Equal(t, ActionLogin, stateManager.lastState.Action)
	require.Equal(t, "github", stateManager.lastState.Provider)
}

func TestHTTPControllerLinkAccountReturnsRedirect(t *testing.T) {
	stateManager := &stubStateManager{}
	provider := &stubProvider{
		name:     "github",
		authBase: "https://auth.example/authorize",
	}

	authenticator := NewSocialAuthenticator(nil, nil, nil, SocialAuthConfig{},
		WithStateManager(stateManager),
		WithProvider(provider),
	)

	controller := NewHTTPController(authenticator, HTTPConfig{
		SessionContextKey: "user",
	})

	ctx := router.NewMockContext()
	ctx.ParamsM["provider"] = "github"
	ctx.LocalsMock["user"] = &auth.JWTClaims{UID: "user-1", UserRole: string(auth.RoleMember)}
	ctx.On("Context").Return(context.Background())

	var payload map[string]string
	ctx.On("JSON", router.StatusOK, mock.Anything).Run(func(args mock.Arguments) {
		payload = args.Get(1).(map[string]string)
	}).Return(nil)

	err := controller.LinkAccount(ctx)
	require.NoError(t, err)
	require.Contains(t, payload["redirect_url"], "state=")
	require.Equal(t, ActionLink, stateManager.lastState.Action)
	require.Equal(t, "user-1", stateManager.lastState.LinkUserID)
}

func TestHTTPControllerCallbackSetsCookieAndRedirects(t *testing.T) {
	stateManager := &stubStateManager{}
	accountRepo := &stubAccountRepo{}
	provider := &stubProvider{
		name:     "github",
		authBase: "https://auth.example/authorize",
		token: &Token{
			AccessToken: "access-token",
		},
		profile: &SocialProfile{
			Provider:       "github",
			ProviderUserID: "provider-user-1",
			Email:          "person@example.com",
			EmailVerified:  true,
			Name:           "Person",
		},
	}

	user := &auth.User{ID: uuid.New(), Status: auth.UserStatusActive}
	linking := &stubLinkingStrategy{
		result: &LinkingResult{
			User:      user,
			IsNewUser: true,
		},
	}

	authenticator := NewSocialAuthenticator(accountRepo, nil, stubTokenService{token: "jwt-token"}, SocialAuthConfig{},
		WithStateManager(stateManager),
		WithLinkingStrategy(linking),
		WithProvider(provider),
	)

	controller := NewHTTPController(authenticator, HTTPConfig{
		SessionContextKey: "user",
		CookieName:        "auth_token",
		CookieSecure:      true,
		CookieHTTPOnly:    true,
		CookieSameSite:    "Lax",
		SuccessRedirect:   "/fallback",
	})

	state := &OAuthState{
		Provider:    "github",
		Action:      ActionLogin,
		RedirectURL: "/dashboard?foo=bar",
		IssuedAt:    time.Now().Unix(),
		ExpiresAt:   time.Now().Add(time.Hour).Unix(),
	}
	stateToken, err := stateManager.Encode(state)
	require.NoError(t, err)

	ctx := router.NewMockContext()
	ctx.ParamsM["provider"] = "github"
	ctx.QueriesM["code"] = "auth-code"
	ctx.QueriesM["state"] = stateToken
	ctx.On("Context").Return(context.Background())
	ctx.On("Cookie", mock.MatchedBy(func(c *router.Cookie) bool {
		return c.Name == "auth_token" && c.Value == "jwt-token" && c.HTTPOnly && c.Secure && c.SameSite == "Lax"
	})).Return()

	var redirectURL string
	ctx.On("Redirect", mock.Anything, []int{http.StatusTemporaryRedirect}).Run(func(args mock.Arguments) {
		redirectURL = args.String(0)
	}).Return(nil)

	err = controller.Callback(ctx)
	require.NoError(t, err)
	require.Len(t, accountRepo.upserts, 1)

	parsed, err := url.Parse(redirectURL)
	require.NoError(t, err)
	require.Equal(t, "bar", parsed.Query().Get("foo"))
	require.Equal(t, "true", parsed.Query().Get("new_user"))
}

func TestHTTPControllerListAccountsReturnsSanitized(t *testing.T) {
	accountRepo := &stubAccountRepo{
		byUser: map[string][]*SocialAccount{
			"user-1": {
				{
					ID:             "acc-1",
					UserID:         "user-1",
					Provider:       "github",
					ProviderUserID: "provider-1",
					Email:          "person@example.com",
					Name:           "Person",
					AvatarURL:      "https://example.com/avatar.png",
					AccessToken:    "secret",
					RefreshToken:   "secret",
					CreatedAt:      time.Now(),
				},
			},
		},
	}

	authenticator := NewSocialAuthenticator(accountRepo, nil, nil, SocialAuthConfig{})
	controller := NewHTTPController(authenticator, HTTPConfig{
		SessionContextKey: "user",
	})

	ctx := router.NewMockContext()
	ctx.LocalsMock["user"] = &auth.JWTClaims{UID: "user-1", UserRole: string(auth.RoleMember)}
	ctx.On("Context").Return(context.Background())

	var payload map[string]any
	ctx.On("JSON", router.StatusOK, mock.Anything).Run(func(args mock.Arguments) {
		payload = args.Get(1).(map[string]any)
	}).Return(nil)

	err := controller.ListAccounts(ctx)
	require.NoError(t, err)

	accounts := payload["accounts"].([]map[string]any)
	require.Len(t, accounts, 1)
	require.Equal(t, "github", accounts[0]["provider"])
	_, hasAccess := accounts[0]["access_token"]
	require.False(t, hasAccess)
	_, hasRefresh := accounts[0]["refresh_token"]
	require.False(t, hasRefresh)
}

func TestHTTPControllerUnlinkAccountRejectsLast(t *testing.T) {
	accountRepo := &stubAccountRepo{
		byUser: map[string][]*SocialAccount{
			"user-1": {
				{
					ID:             "acc-1",
					UserID:         "user-1",
					Provider:       "github",
					ProviderUserID: "provider-1",
				},
			},
		},
	}

	authenticator := NewSocialAuthenticator(accountRepo, nil, nil, SocialAuthConfig{})
	controller := NewHTTPController(authenticator, HTTPConfig{
		SessionContextKey: "user",
	})

	ctx := router.NewMockContext()
	ctx.ParamsM["provider"] = "github"
	ctx.LocalsMock["user"] = &auth.JWTClaims{UID: "user-1", UserRole: string(auth.RoleMember)}
	ctx.On("Context").Return(context.Background())
	ctx.On("JSON", router.StatusBadRequest, mock.Anything).Return(nil)

	err := controller.UnlinkAccount(ctx)
	require.NoError(t, err)
	require.Empty(t, accountRepo.deleteCalls)
}
