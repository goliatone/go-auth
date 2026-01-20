package auth0

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/auth0/go-auth0/management"
	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
)

const (
	// IdentifierProviderAuth0 is the provider name used for Auth0 identifiers.
	IdentifierProviderAuth0 = "auth0"
)

// IdentityProviderConfig configures the Auth0 identity provider.
type IdentityProviderConfig struct {
	// ManagementDomain is the Auth0 management API domain.
	ManagementDomain string

	// ClientID is the M2M application client ID.
	ClientID string

	// ClientSecret is the M2M application client secret.
	ClientSecret string

	// LocalUsers is an optional local user repository for caching/enrichment.
	LocalUsers auth.Users

	// IdentifierStore maps external identifiers to local users (new table).
	IdentifierStore IdentifierStore

	// SyncOnFetch enables automatic local sync when fetching users.
	SyncOnFetch bool
}

// IdentifierStore maps external identifiers (Auth0, Slack, etc) to a user.
type IdentifierStore interface {
	FindUserID(ctx context.Context, provider, identifier string) (string, error)
	Upsert(ctx context.Context, userID, provider, identifier string) error
}

// IdentityProvider implements auth.IdentityProvider backed by Auth0.
type IdentityProvider struct {
	config          IdentityProviderConfig
	mgmt            *management.Management
	localUsers      auth.Users
	identifierStore IdentifierStore
}

// NewIdentityProvider creates an Auth0-backed identity provider.
func NewIdentityProvider(ctx context.Context, cfg IdentityProviderConfig) (*IdentityProvider, error) {
	if strings.TrimSpace(cfg.ManagementDomain) == "" {
		return nil, fmt.Errorf("auth0: management domain is required")
	}

	mgmt, err := management.New(
		cfg.ManagementDomain,
		management.WithClientCredentials(ctx, cfg.ClientID, cfg.ClientSecret),
	)
	if err != nil {
		return nil, fmt.Errorf("auth0: failed to create management client: %w", err)
	}

	return &IdentityProvider{
		config:          cfg,
		mgmt:            mgmt,
		localUsers:      cfg.LocalUsers,
		identifierStore: cfg.IdentifierStore,
	}, nil
}

// FindIdentityByIdentifier implements auth.IdentityProvider.
func (p *IdentityProvider) FindIdentityByIdentifier(ctx context.Context, identifier string) (auth.Identity, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, auth.ErrIdentityNotFound
	}

	if p.identifierStore != nil && p.localUsers != nil {
		userID, err := p.identifierStore.FindUserID(ctx, IdentifierProviderAuth0, identifier)
		if err == nil && userID != "" {
			localUser, err := p.localUsers.GetByIdentifier(ctx, userID)
			if err == nil && localUser != nil {
				return auth.NewIdentityFromUser(localUser), nil
			}
			if err != nil && !repository.IsRecordNotFound(err) && err != sql.ErrNoRows {
				return nil, fmt.Errorf("auth0: failed to resolve local user: %w", err)
			}
		} else if err != nil && !repository.IsRecordNotFound(err) && err != sql.ErrNoRows {
			return nil, fmt.Errorf("auth0: failed to resolve identifier: %w", err)
		}
	}

	auth0User, err := p.mgmt.User.Read(ctx, identifier)
	if err != nil {
		return nil, fmt.Errorf("auth0: user not found: %w", err)
	}

	user := p.mapAuth0User(auth0User)

	if p.config.SyncOnFetch && p.localUsers != nil {
		_, _ = p.syncToLocal(ctx, user)
	}

	return user, nil
}

// VerifyIdentity is not supported for Auth0 provider (Auth0 handles authentication).
func (p *IdentityProvider) VerifyIdentity(ctx context.Context, identifier, password string) (auth.Identity, error) {
	return nil, fmt.Errorf("auth0: direct password verification not supported; use Auth0 login flow")
}

func (p *IdentityProvider) mapAuth0User(u *management.User) *Auth0Identity {
	if u == nil {
		return nil
	}

	metadata := map[string]any{}
	if u.AppMetadata != nil {
		for k, v := range *u.AppMetadata {
			metadata[k] = v
		}
	}

	role := roleFromMetadata(metadata)
	if role == "" && u.UserMetadata != nil {
		role = roleFromMetadata(*u.UserMetadata)
	}

	return &Auth0Identity{
		id:            u.GetID(),
		email:         u.GetEmail(),
		emailVerified: u.GetEmailVerified(),
		name:          u.GetName(),
		nickname:      u.GetNickname(),
		picture:       u.GetPicture(),
		role:          role,
		metadata:      metadata,
	}
}

func roleFromMetadata(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}

	if raw, ok := metadata["role"]; ok {
		if role, ok := raw.(string); ok {
			return role
		}
	}

	return ""
}

func (p *IdentityProvider) syncToLocal(ctx context.Context, identity *Auth0Identity) (*auth.User, error) {
	if p.localUsers == nil || identity == nil {
		return nil, nil
	}

	localUser := mapIdentityToUser(identity)
	if localUser == nil {
		return nil, nil
	}

	if p.identifierStore != nil && identity.id != "" {
		localID, err := p.identifierStore.FindUserID(ctx, IdentifierProviderAuth0, identity.id)
		if err == nil && localID != "" {
			if parsed, parseErr := uuid.Parse(localID); parseErr == nil {
				localUser.ID = parsed
			}
		} else if err != nil && !repository.IsRecordNotFound(err) && err != sql.ErrNoRows {
			return nil, err
		}
	}

	if localUser.Email == "" && localUser.ID == uuid.Nil {
		localUser.ID = uuid.New()
	}

	localUser, err := p.localUsers.Upsert(ctx, localUser, repository.UpdateSkipZeroValues())
	if err != nil {
		return nil, err
	}

	if p.identifierStore != nil && identity.id != "" {
		_ = p.identifierStore.Upsert(ctx, localUser.ID.String(), IdentifierProviderAuth0, identity.id)
	}

	return localUser, nil
}

func mapIdentityToUser(identity *Auth0Identity) *auth.User {
	if identity == nil {
		return nil
	}

	firstName, lastName := splitName(identity.name)
	if firstName == "" && identity.nickname != "" {
		firstName = identity.nickname
	}

	username := identity.nickname
	if username == "" && identity.email != "" {
		username = strings.SplitN(identity.email, "@", 2)[0]
	}
	if username == "" {
		username = sanitizeIdentifier(identity.id)
	}

	role := auth.RoleMember
	if identity.role != "" {
		if parsed, ok := auth.ParseRole(identity.role); ok {
			role = parsed
		}
	}

	metadata := map[string]any{
		"auth0_id":       identity.id,
		"auth0_provider": IdentifierProviderAuth0,
	}
	if identity.metadata != nil {
		metadata["auth0_metadata"] = identity.metadata
	}

	return &auth.User{
		Role:           role,
		Status:         auth.UserStatusActive,
		FirstName:      firstName,
		LastName:       lastName,
		Username:       username,
		Email:          identity.email,
		EmailValidated: identity.emailVerified,
		ProfilePicture: identity.picture,
		Metadata:       metadata,
	}
}

func splitName(name string) (string, string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", ""
	}

	parts := strings.SplitN(name, " ", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

func sanitizeIdentifier(identifier string) string {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return "user"
	}
	cleaned := strings.NewReplacer("|", "_", ":", "_", "@", "_", " ", "_").Replace(identifier)
	if cleaned == "" {
		return "user"
	}
	return cleaned
}

// Auth0Identity represents an Auth0 user implementing auth.Identity.
type Auth0Identity struct {
	id            string
	email         string
	emailVerified bool
	name          string
	nickname      string
	picture       string
	role          string
	metadata      map[string]any
}

func (u *Auth0Identity) ID() string       { return u.id }
func (u *Auth0Identity) Username() string { return u.nickname }
func (u *Auth0Identity) Email() string    { return u.email }
func (u *Auth0Identity) Role() string     { return u.role }
func (u *Auth0Identity) Name() string     { return u.name }
func (u *Auth0Identity) Picture() string  { return u.picture }
func (u *Auth0Identity) Metadata() map[string]any {
	if u == nil {
		return nil
	}
	return u.metadata
}
