package sync

import (
	"context"
	"fmt"
	"strings"

	"github.com/auth0/go-auth0/management"
)

// ManagementConfig configures the Auth0 management client.
type ManagementConfig struct {
	Domain       string
	ClientID     string
	ClientSecret string
	Client       *management.Management
}

// ManagementClient wraps the Auth0 management API client.
type ManagementClient struct {
	client *management.Management
}

// NewManagementClient creates a new management client wrapper.
func NewManagementClient(ctx context.Context, cfg ManagementConfig) (*ManagementClient, error) {
	if cfg.Client != nil {
		return &ManagementClient{client: cfg.Client}, nil
	}

	domain := strings.TrimSpace(cfg.Domain)
	if domain == "" {
		return nil, fmt.Errorf("auth0 management: domain is required")
	}

	client, err := management.New(
		domain,
		management.WithClientCredentials(ctx, cfg.ClientID, cfg.ClientSecret),
	)
	if err != nil {
		return nil, fmt.Errorf("auth0 management: failed to create client: %w", err)
	}

	return &ManagementClient{client: client}, nil
}

// GetUser fetches an Auth0 user by identifier.
func (m *ManagementClient) GetUser(ctx context.Context, identifier string) (*management.User, error) {
	if m == nil || m.client == nil {
		return nil, fmt.Errorf("auth0 management: client not initialized")
	}

	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, fmt.Errorf("auth0 management: identifier is required")
	}

	user, err := m.client.User.Read(ctx, identifier)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// UpdateUser updates an Auth0 user.
func (m *ManagementClient) UpdateUser(ctx context.Context, identifier string, user *management.User) error {
	if m == nil || m.client == nil {
		return fmt.Errorf("auth0 management: client not initialized")
	}

	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return fmt.Errorf("auth0 management: identifier is required")
	}

	return m.client.User.Update(ctx, identifier, user)
}

// RawClient exposes the underlying management client.
func (m *ManagementClient) RawClient() *management.Management {
	if m == nil {
		return nil
	}
	return m.client
}
