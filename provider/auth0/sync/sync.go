package sync

import (
	"context"
	"fmt"
	"strings"

	"github.com/auth0/go-auth0/management"
	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/auth0"
	"github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
)

// UserMapper maps an Auth0 management user into a local auth.User.
type UserMapper func(ctx context.Context, user *management.User) (*auth.User, error)

// Config configures the Auth0 sync service.
type Config struct {
	Users           auth.Users
	IdentifierStore auth0.IdentifierStore
	Provider        string
	UserMapper      UserMapper
}

// Service synchronizes Auth0 users into the local store.
type Service struct {
	users           auth.Users
	identifierStore auth0.IdentifierStore
	provider        string
	userMapper      UserMapper
}

// NewService creates a new sync service.
func NewService(cfg Config) *Service {
	provider := strings.TrimSpace(cfg.Provider)
	if provider == "" {
		provider = auth0.IdentifierProviderAuth0
	}

	mapper := cfg.UserMapper
	if mapper == nil {
		mapper = DefaultUserMapper
	}

	return &Service{
		users:           cfg.Users,
		identifierStore: cfg.IdentifierStore,
		provider:        provider,
		userMapper:      mapper,
	}
}

// SyncUser upserts the Auth0 user into the local user store.
func (s *Service) SyncUser(ctx context.Context, user *management.User) (*auth.User, error) {
	if s == nil || s.users == nil {
		return nil, fmt.Errorf("auth0 sync: users repository is required")
	}
	if user == nil {
		return nil, fmt.Errorf("auth0 sync: user is required")
	}

	localUser, err := s.userMapper(ctx, user)
	if err != nil {
		return nil, err
	}
	if localUser == nil {
		return nil, fmt.Errorf("auth0 sync: user mapper returned nil")
	}

	if s.identifierStore != nil {
		localID, err := s.identifierStore.FindUserID(ctx, s.provider, user.GetID())
		if err == nil && localID != "" {
			if parsed, parseErr := uuid.Parse(localID); parseErr == nil {
				localUser.ID = parsed
			}
		}
	}

	if localUser.Email == "" && localUser.ID == uuid.Nil {
		localUser.ID = uuid.New()
	}

	localUser, err = s.users.Upsert(ctx, localUser, repository.UpdateSkipZeroValues())
	if err != nil {
		return nil, err
	}

	if s.identifierStore != nil && user.GetID() != "" {
		_ = s.identifierStore.Upsert(ctx, localUser.ID.String(), s.provider, user.GetID())
	}

	return localUser, nil
}

// SyncByID fetches an Auth0 user and synchronizes it into the local store.
func (s *Service) SyncByID(ctx context.Context, mgmt *ManagementClient, identifier string) (*auth.User, error) {
	if mgmt == nil {
		return nil, fmt.Errorf("auth0 sync: management client is required")
	}

	user, err := mgmt.GetUser(ctx, identifier)
	if err != nil {
		return nil, err
	}

	return s.SyncUser(ctx, user)
}

// DefaultUserMapper provides a baseline Auth0 -> local user mapping.
func DefaultUserMapper(ctx context.Context, user *management.User) (*auth.User, error) {
	if user == nil {
		return nil, fmt.Errorf("auth0 sync: user is required")
	}

	firstName, lastName := splitName(user.GetName())
	if firstName == "" && user.GetNickname() != "" {
		firstName = user.GetNickname()
	}

	username := firstNonEmpty(user.GetNickname(), user.GetUsername())
	if username == "" && user.GetEmail() != "" {
		username = strings.SplitN(user.GetEmail(), "@", 2)[0]
	}
	if username == "" {
		username = sanitizeIdentifier(user.GetID())
	}

	role := auth.RoleMember
	if mapped := roleFromMetadata(mapFromMetadataPointer(user.AppMetadata)); mapped != "" {
		if parsed, ok := auth.ParseRole(mapped); ok {
			role = parsed
		}
	} else if mapped := roleFromMetadata(mapFromMetadataPointer(user.UserMetadata)); mapped != "" {
		if parsed, ok := auth.ParseRole(mapped); ok {
			role = parsed
		}
	}

	metadata := map[string]any{
		"auth0_id":       user.GetID(),
		"auth0_provider": auth0.IdentifierProviderAuth0,
	}
	if appMetadata := mapFromMetadataPointer(user.AppMetadata); appMetadata != nil {
		metadata["auth0_app_metadata"] = copyMap(appMetadata)
	}
	if userMetadata := mapFromMetadataPointer(user.UserMetadata); userMetadata != nil {
		metadata["auth0_user_metadata"] = copyMap(userMetadata)
	}

	return &auth.User{
		Role:           role,
		Status:         auth.UserStatusActive,
		FirstName:      firstName,
		LastName:       lastName,
		Username:       username,
		Email:          user.GetEmail(),
		EmailValidated: user.GetEmailVerified(),
		ProfilePicture: user.GetPicture(),
		Metadata:       metadata,
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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

func mapFromMetadataPointer(metadata *map[string]any) map[string]any {
	if metadata == nil {
		return nil
	}

	out := make(map[string]any, len(*metadata))
	for key, value := range *metadata {
		out[key] = value
	}

	return out
}

func copyMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}

	copy := make(map[string]any, len(source))
	for k, v := range source {
		copy[k] = v
	}
	return copy
}
