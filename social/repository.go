package social

import (
	"context"
	"time"
)

// SocialAccount represents a linked social provider account.
type SocialAccount struct {
	ID             string         `json:"id"`
	UserID         string         `json:"user_id"`
	Provider       string         `json:"provider"`
	ProviderUserID string         `json:"provider_user_id"`
	Email          string         `json:"email,omitempty"`
	Name           string         `json:"name,omitempty"`
	Username       string         `json:"username,omitempty"`
	AvatarURL      string         `json:"avatar_url,omitempty"`
	AccessToken    string         `json:"-"`
	RefreshToken   string         `json:"-"`
	TokenExpiresAt *time.Time     `json:"token_expires_at,omitempty"`
	ProfileData    map[string]any `json:"profile_data,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// SocialAccountRepository manages social account persistence.
type SocialAccountRepository interface {
	FindByProviderID(ctx context.Context, provider, providerUserID string) (*SocialAccount, error)
	FindByUserID(ctx context.Context, userID string) ([]*SocialAccount, error)
	Upsert(ctx context.Context, account *SocialAccount) error
	Delete(ctx context.Context, id string) error
	DeleteByUserAndProvider(ctx context.Context, userID, provider string) error
}
