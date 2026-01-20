package social

import (
	"context"
	"database/sql"
	"testing"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubLinkingAccountRepo struct {
	byProviderID map[string]*SocialAccount
}

func (s *stubLinkingAccountRepo) FindByProviderID(ctx context.Context, provider, providerUserID string) (*SocialAccount, error) {
	if account, ok := s.byProviderID[accountKey(provider, providerUserID)]; ok {
		return account, nil
	}
	return nil, sql.ErrNoRows
}

func (s *stubLinkingAccountRepo) FindByUserID(ctx context.Context, userID string) ([]*SocialAccount, error) {
	return nil, nil
}

func (s *stubLinkingAccountRepo) Upsert(ctx context.Context, account *SocialAccount) error {
	if s.byProviderID == nil {
		s.byProviderID = map[string]*SocialAccount{}
	}
	s.byProviderID[accountKey(account.Provider, account.ProviderUserID)] = account
	return nil
}

func (s *stubLinkingAccountRepo) Delete(ctx context.Context, id string) error {
	return nil
}

func (s *stubLinkingAccountRepo) DeleteByUserAndProvider(ctx context.Context, userID, provider string) error {
	return nil
}

type stubUsers struct {
	auth.Users
	byIdentifier map[string]*auth.User
	created      []*auth.User
	createErr    error
	getErr       map[string]error
}

func (s *stubUsers) GetByIdentifier(ctx context.Context, identifier string, criteria ...repository.SelectCriteria) (*auth.User, error) {
	if s.getErr != nil {
		if err, ok := s.getErr[identifier]; ok {
			return nil, err
		}
	}
	if user, ok := s.byIdentifier[identifier]; ok {
		return user, nil
	}
	return nil, sql.ErrNoRows
}

func (s *stubUsers) Create(ctx context.Context, record *auth.User, criteria ...repository.InsertCriteria) (*auth.User, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	if record.ID == uuid.Nil {
		record.ID = uuid.New()
	}
	s.created = append(s.created, record)
	if s.byIdentifier == nil {
		s.byIdentifier = map[string]*auth.User{}
	}
	if record.Email != "" {
		s.byIdentifier[record.Email] = record
	}
	s.byIdentifier[record.ID.String()] = record
	return record, nil
}

func TestDefaultLinkingStrategy_ExistingAccount(t *testing.T) {
	user := &auth.User{ID: uuid.New(), Email: "existing@example.com"}
	accountRepo := &stubLinkingAccountRepo{
		byProviderID: map[string]*SocialAccount{
			accountKey("github", "123"): {
				UserID:         user.ID.String(),
				Provider:       "github",
				ProviderUserID: "123",
			},
		},
	}
	userRepo := &stubUsers{
		byIdentifier: map[string]*auth.User{
			user.ID.String(): user,
		},
	}

	strategy := &DefaultLinkingStrategy{
		AllowSignup:          true,
		AllowLinking:         true,
		RequireEmailVerified: true,
	}

	result, err := strategy.ResolveUser(context.Background(), LinkingContext{
		Profile: &SocialProfile{
			Provider:       "github",
			ProviderUserID: "123",
			EmailVerified:  true,
		},
		AccountRepo: accountRepo,
		UserRepo:    userRepo,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, user, result.User)
	assert.False(t, result.IsNewUser)
}

func TestDefaultLinkingStrategy_CreatesNewUser(t *testing.T) {
	accountRepo := &stubAccountRepo{}
	userRepo := &stubUsers{}

	strategy := &DefaultLinkingStrategy{
		AllowSignup:          true,
		AllowLinking:         true,
		RequireEmailVerified: true,
		DefaultRole:          "member",
	}

	profile := &SocialProfile{
		Provider:       "github",
		ProviderUserID: "456",
		Email:          "new@example.com",
		EmailVerified:  true,
		Name:           "New User",
		AvatarURL:      "https://example.com/avatar.png",
	}

	result, err := strategy.ResolveUser(context.Background(), LinkingContext{
		Profile:     profile,
		Action:      ActionLogin,
		AccountRepo: accountRepo,
		UserRepo:    userRepo,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsNewUser)
	require.Len(t, userRepo.created, 1)
	assert.Equal(t, profile.Email, result.User.Email)
	assert.Equal(t, auth.UserStatusActive, result.User.Status)
}

func TestDefaultLinkingStrategy_BlockedExistingEmail(t *testing.T) {
	user := &auth.User{ID: uuid.New(), Email: "exists@example.com"}
	accountRepo := &stubAccountRepo{}
	userRepo := &stubUsers{
		byIdentifier: map[string]*auth.User{
			user.Email: user,
		},
	}

	strategy := &DefaultLinkingStrategy{
		AllowSignup:          true,
		AllowLinking:         false,
		RequireEmailVerified: true,
	}

	_, err := strategy.ResolveUser(context.Background(), LinkingContext{
		Profile: &SocialProfile{
			Provider:      "github",
			Email:         user.Email,
			EmailVerified: true,
		},
		AccountRepo: accountRepo,
		UserRepo:    userRepo,
	})
	assert.ErrorIs(t, err, ErrEmailAlreadyExists)
}

func accountKey(provider, providerUserID string) string {
	return provider + ":" + providerUserID
}
