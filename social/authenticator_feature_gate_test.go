package social

import (
	"context"
	"testing"
	"time"

	"github.com/goliatone/go-featuregate/gate"
	"github.com/stretchr/testify/require"
)

type stubFeatureGate struct {
	enabled map[string]bool
	calls   []string
	err     error
}

func (s *stubFeatureGate) Enabled(ctx context.Context, key string, opts ...gate.ResolveOption) (bool, error) {
	s.calls = append(s.calls, key)
	if s.err != nil {
		return false, s.err
	}
	if s.enabled == nil {
		return true, nil
	}
	enabled, ok := s.enabled[key]
	if !ok {
		return true, nil
	}
	return enabled, nil
}

type trackingProvider struct {
	name          string
	exchangeCalls int
}

func (p *trackingProvider) Name() string {
	return p.name
}

func (p *trackingProvider) AuthCodeURL(state string, opts ...AuthCodeOption) string {
	return "https://auth.example/authorize?state=" + state
}

func (p *trackingProvider) Exchange(ctx context.Context, code string, opts ...ExchangeOption) (*Token, error) {
	p.exchangeCalls++
	return &Token{AccessToken: "token"}, nil
}

func (p *trackingProvider) UserInfo(ctx context.Context, token *Token) (*SocialProfile, error) {
	return &SocialProfile{}, nil
}

func (p *trackingProvider) ValidateToken(ctx context.Context, token *Token) error {
	return nil
}

func (p *trackingProvider) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	return nil, nil
}

func TestSocialAuthenticatorBeginAuthSignupDeniedByFeatureGate(t *testing.T) {
	stateManager := &stubStateManager{}
	provider := &stubProvider{
		name:     "github",
		authBase: "https://auth.example/authorize",
	}
	stubGate := &stubFeatureGate{
		enabled: map[string]bool{
			gate.FeatureUsersSignup: false,
		},
	}

	authenticator := NewSocialAuthenticator(nil, nil, nil, SocialAuthConfig{},
		WithStateManager(stateManager),
		WithProvider(provider),
		WithFeatureGate(stubGate),
	)

	_, err := authenticator.BeginAuth(context.Background(), "github", ForAction(ActionSignup))
	require.ErrorIs(t, err, ErrSignupNotAllowed)
	require.Equal(t, []string{gate.FeatureUsersSignup}, stubGate.calls)
}

func TestSocialAuthenticatorCompleteAuthSignupDeniedByFeatureGate(t *testing.T) {
	stateManager := &stubStateManager{}
	provider := &trackingProvider{name: "github"}
	stubGate := &stubFeatureGate{
		enabled: map[string]bool{
			gate.FeatureUsersSignup: false,
		},
	}

	authenticator := NewSocialAuthenticator(nil, nil, nil, SocialAuthConfig{},
		WithStateManager(stateManager),
		WithProvider(provider),
		WithFeatureGate(stubGate),
	)

	state := &OAuthState{
		Provider:  "github",
		Action:    ActionSignup,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	stateToken, err := stateManager.Encode(state)
	require.NoError(t, err)

	_, err = authenticator.CompleteAuth(context.Background(), "github", "code", stateToken)
	require.ErrorIs(t, err, ErrSignupNotAllowed)
	require.Equal(t, 0, provider.exchangeCalls)
	require.Equal(t, []string{gate.FeatureUsersSignup}, stubGate.calls)
}
