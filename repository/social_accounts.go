package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/goliatone/go-auth/social"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// SocialAccountModel is the Bun model for social accounts.
type SocialAccountModel struct {
	bun.BaseModel `bun:"table:social_accounts"`

	ID             uuid.UUID      `bun:"id,pk,nullzero,type:uuid"`
	UserID         uuid.UUID      `bun:"user_id,notnull,type:uuid"`
	Provider       string         `bun:"provider,notnull"`
	ProviderUserID string         `bun:"provider_user_id,notnull"`
	Email          string         `bun:"email"`
	Name           string         `bun:"name"`
	Username       string         `bun:"username"`
	AvatarURL      string         `bun:"avatar_url"`
	AccessToken    string         `bun:"access_token"`
	RefreshToken   string         `bun:"refresh_token"`
	TokenExpiresAt *time.Time     `bun:"token_expires_at"`
	ProfileData    map[string]any `bun:"profile_data,type:jsonb"`
	CreatedAt      time.Time      `bun:"created_at,default:current_timestamp"`
	UpdatedAt      time.Time      `bun:"updated_at,default:current_timestamp"`
}

// SocialAccountRepository implements social.SocialAccountRepository using Bun.
type SocialAccountRepository struct {
	db *bun.DB
}

// NewSocialAccountRepository creates a new repository.
func NewSocialAccountRepository(db *bun.DB) *SocialAccountRepository {
	return &SocialAccountRepository{db: db}
}

// FindByProviderID implements social.SocialAccountRepository.
func (r *SocialAccountRepository) FindByProviderID(ctx context.Context, provider, providerUserID string) (*social.SocialAccount, error) {
	var model SocialAccountModel
	err := r.db.NewSelect().
		Model(&model).
		Where("provider = ? AND provider_user_id = ?", provider, providerUserID).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return r.toSocialAccount(&model), nil
}

// FindByUserID implements social.SocialAccountRepository.
func (r *SocialAccountRepository) FindByUserID(ctx context.Context, userID string) ([]*social.SocialAccount, error) {
	var models []SocialAccountModel
	err := r.db.NewSelect().
		Model(&models).
		Where("user_id = ?", userID).
		Scan(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return []*social.SocialAccount{}, nil
		}
		return nil, err
	}

	accounts := make([]*social.SocialAccount, len(models))
	for i, m := range models {
		accounts[i] = r.toSocialAccount(&m)
	}
	return accounts, nil
}

// Upsert implements social.SocialAccountRepository.
func (r *SocialAccountRepository) Upsert(ctx context.Context, account *social.SocialAccount) error {
	model := r.fromSocialAccount(account)
	model.UpdatedAt = time.Now()

	_, err := r.db.NewInsert().
		Model(model).
		On("CONFLICT (provider, provider_user_id) DO UPDATE").
		Set("user_id = EXCLUDED.user_id").
		Set("email = EXCLUDED.email").
		Set("name = EXCLUDED.name").
		Set("username = EXCLUDED.username").
		Set("avatar_url = EXCLUDED.avatar_url").
		Set("access_token = EXCLUDED.access_token").
		Set("refresh_token = EXCLUDED.refresh_token").
		Set("token_expires_at = EXCLUDED.token_expires_at").
		Set("profile_data = EXCLUDED.profile_data").
		Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)

	return err
}

// Delete implements social.SocialAccountRepository.
func (r *SocialAccountRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.NewDelete().
		Model((*SocialAccountModel)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// DeleteByUserAndProvider implements social.SocialAccountRepository.
func (r *SocialAccountRepository) DeleteByUserAndProvider(ctx context.Context, userID, provider string) error {
	_, err := r.db.NewDelete().
		Model((*SocialAccountModel)(nil)).
		Where("user_id = ? AND provider = ?", userID, provider).
		Exec(ctx)
	return err
}

func (r *SocialAccountRepository) toSocialAccount(m *SocialAccountModel) *social.SocialAccount {
	acc := &social.SocialAccount{
		ID:             m.ID.String(),
		UserID:         m.UserID.String(),
		Provider:       m.Provider,
		ProviderUserID: m.ProviderUserID,
		Email:          m.Email,
		Name:           m.Name,
		Username:       m.Username,
		AvatarURL:      m.AvatarURL,
		AccessToken:    m.AccessToken,
		RefreshToken:   m.RefreshToken,
		ProfileData:    m.ProfileData,
		CreatedAt:      m.CreatedAt,
		UpdatedAt:      m.UpdatedAt,
	}
	acc.TokenExpiresAt = m.TokenExpiresAt
	return acc
}

func (r *SocialAccountRepository) fromSocialAccount(a *social.SocialAccount) *SocialAccountModel {
	if a == nil {
		return &SocialAccountModel{
			ID:          uuid.New(),
			ProfileData: map[string]any{},
		}
	}

	var id uuid.UUID
	if a.ID != "" {
		if parsed, err := uuid.Parse(a.ID); err == nil {
			id = parsed
		}
	}
	if id == uuid.Nil {
		id = uuid.New()
	}

	var userID uuid.UUID
	if a.UserID != "" {
		if parsed, err := uuid.Parse(a.UserID); err == nil {
			userID = parsed
		}
	}

	profileData := map[string]any{}
	if a.ProfileData != nil {
		profileData = a.ProfileData
	}

	model := &SocialAccountModel{
		ID:             id,
		UserID:         userID,
		Provider:       a.Provider,
		ProviderUserID: a.ProviderUserID,
		Email:          a.Email,
		Name:           a.Name,
		Username:       a.Username,
		AvatarURL:      a.AvatarURL,
		AccessToken:    a.AccessToken,
		RefreshToken:   a.RefreshToken,
		ProfileData:    profileData,
		CreatedAt:      a.CreatedAt,
		UpdatedAt:      a.UpdatedAt,
	}
	model.TokenExpiresAt = a.TokenExpiresAt
	return model
}
