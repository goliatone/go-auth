package social

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-repository-bun"
)

// LinkingStrategy determines how social profiles are linked to users.
type LinkingStrategy interface {
	ResolveUser(ctx context.Context, lc LinkingContext) (*LinkingResult, error)
}

// LinkingPolicy decides which linking mode/flags to apply for a request.
type LinkingPolicy func(ctx context.Context, lc LinkingContext) (LinkDecision, error)

// LinkDecision controls resolution behavior for a single auth flow.
type LinkDecision struct {
	Mode                 string
	AllowSignup          bool
	AllowLinking         bool
	RequireEmailVerified bool
}

// PolicyLinkingStrategy applies a LinkingPolicy and then performs resolution.
type PolicyLinkingStrategy struct {
	Policy LinkingPolicy
}

// ResolveUser implements LinkingStrategy.
func (s *PolicyLinkingStrategy) ResolveUser(ctx context.Context, lc LinkingContext) (*LinkingResult, error) {
	if s == nil || s.Policy == nil {
		return nil, ErrLinkingNotAllowed
	}

	decision, err := s.Policy(ctx, lc)
	if err != nil {
		return nil, err
	}

	resolver := &DefaultLinkingStrategy{
		AllowSignup:          decision.AllowSignup,
		AllowLinking:         decision.AllowLinking,
		RequireEmailVerified: decision.RequireEmailVerified,
	}

	return resolver.ResolveUser(ctx, lc.withMode(decision.Mode))
}

// LinkingContext provides context for user resolution.
type LinkingContext struct {
	Profile     *SocialProfile
	Action      string
	Mode        string
	LinkUserID  string
	AccountRepo SocialAccountRepository
	UserRepo    auth.Users
}

func (lc LinkingContext) withMode(mode string) LinkingContext {
	if mode == "" {
		return lc
	}
	copy := lc
	copy.Mode = mode
	return copy
}

// LinkingResult contains the resolved user and metadata.
type LinkingResult struct {
	User      *auth.User
	IsNewUser bool
	Linked    bool
}

// DefaultLinkingStrategy implements common linking logic.
type DefaultLinkingStrategy struct {
	AllowSignup          bool
	AllowLinking         bool
	RequireEmailVerified bool
	DefaultRole          string

	OnUserCreated   func(ctx context.Context, user *auth.User, profile *SocialProfile) error
	OnAccountLinked func(ctx context.Context, user *auth.User, profile *SocialProfile) error
}

// ResolveUser implements LinkingStrategy.
func (s *DefaultLinkingStrategy) ResolveUser(ctx context.Context, lc LinkingContext) (*LinkingResult, error) {
	if err := s.validateContext(lc); err != nil {
		return nil, err
	}

	result, found, err := s.findLinkedUser(ctx, lc)
	if err != nil || found {
		return result, err
	}

	if lc.Action == ActionLink && lc.LinkUserID != "" {
		return s.linkRequestedUser(ctx, lc)
	}

	if lc.Mode == LinkModeExplicitOnly {
		return nil, ErrLinkingNotAllowed
	}

	result, found, err = s.findUserByEmail(ctx, lc)
	if err != nil || found {
		return result, err
	}

	if lc.Mode == LinkModeEmailMatch || lc.Mode == LinkModeRejectUnknown {
		return nil, ErrSignupNotAllowed
	}

	if !s.AllowSignup {
		return nil, ErrSignupNotAllowed
	}

	return s.createNewUser(ctx, lc)
}

func (s *DefaultLinkingStrategy) validateContext(lc LinkingContext) error {
	if lc.Profile == nil {
		return ErrUserInfoFailed
	}
	if lc.AccountRepo == nil || lc.UserRepo == nil {
		return ErrLinkingNotAllowed
	}
	if s.RequireEmailVerified && !lc.Profile.EmailVerified {
		return ErrEmailNotVerified
	}
	return nil
}

func (s *DefaultLinkingStrategy) findLinkedUser(ctx context.Context, lc LinkingContext) (*LinkingResult, bool, error) {
	profile := lc.Profile
	existing, err := lc.AccountRepo.FindByProviderID(ctx, profile.Provider, profile.ProviderUserID)
	if err != nil {
		if repository.IsRecordNotFound(err) || err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to find linked account: %w", err)
	}
	if existing == nil {
		return nil, false, nil
	}

	user, err := lc.UserRepo.GetByIdentifier(ctx, existing.UserID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to find linked user: %w", err)
	}
	return &LinkingResult{User: user, IsNewUser: false}, true, nil
}

func (s *DefaultLinkingStrategy) linkRequestedUser(ctx context.Context, lc LinkingContext) (*LinkingResult, error) {
	if !s.AllowLinking {
		return nil, ErrLinkingNotAllowed
	}

	user, err := lc.UserRepo.GetByIdentifier(ctx, lc.LinkUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user to link: %w", err)
	}
	if err := s.notifyAccountLinked(ctx, user, lc.Profile); err != nil {
		return nil, err
	}
	return &LinkingResult{User: user, IsNewUser: false, Linked: true}, nil
}

func (s *DefaultLinkingStrategy) findUserByEmail(ctx context.Context, lc LinkingContext) (*LinkingResult, bool, error) {
	profile := lc.Profile
	if profile.Email == "" || lc.Mode == LinkModeRejectUnknown {
		return nil, false, nil
	}

	user, err := lc.UserRepo.GetByIdentifier(ctx, profile.Email)
	if err != nil {
		if repository.IsRecordNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to find user by email: %w", err)
	}
	if user == nil {
		return nil, false, nil
	}

	if !s.AllowLinking {
		return nil, false, ErrEmailAlreadyExists
	}
	if err := s.notifyAccountLinked(ctx, user, profile); err != nil {
		return nil, false, err
	}
	return &LinkingResult{User: user, IsNewUser: false, Linked: true}, true, nil
}

func (s *DefaultLinkingStrategy) notifyAccountLinked(ctx context.Context, user *auth.User, profile *SocialProfile) error {
	if s.OnAccountLinked == nil {
		return nil
	}
	return s.OnAccountLinked(ctx, user, profile)
}

func (s *DefaultLinkingStrategy) createNewUser(ctx context.Context, lc LinkingContext) (*LinkingResult, error) {
	profile := lc.Profile
	newUser := s.createUserFromProfile(profile)
	created, err := lc.UserRepo.Create(ctx, newUser)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if s.OnUserCreated != nil {
		if err := s.OnUserCreated(ctx, created, profile); err != nil {
			return nil, err
		}
	}

	return &LinkingResult{User: created, IsNewUser: true}, nil
}

func (s *DefaultLinkingStrategy) createUserFromProfile(profile *SocialProfile) *auth.User {
	role := auth.RoleMember
	if s.DefaultRole != "" {
		if parsed, ok := auth.ParseRole(s.DefaultRole); ok {
			role = parsed
		}
	}

	user := &auth.User{
		Email:          profile.Email,
		EmailValidated: profile.EmailVerified,
		Role:           role,
		Status:         auth.UserStatusActive,
		ProfilePicture: profile.AvatarURL,
		Metadata: map[string]any{
			"social_provider": profile.Provider,
			"avatar_url":      profile.AvatarURL,
		},
	}

	if profile.FirstName != "" {
		user.FirstName = profile.FirstName
		user.LastName = profile.LastName
	} else if profile.Name != "" {
		parts := strings.SplitN(profile.Name, " ", 2)
		user.FirstName = parts[0]
		if len(parts) > 1 {
			user.LastName = parts[1]
		}
	}

	if profile.Username != "" {
		user.Username = profile.Username
	} else if profile.Email != "" {
		user.Username = strings.Split(profile.Email, "@")[0]
	} else if profile.ProviderUserID != "" {
		user.Username = fmt.Sprintf("%s_%s", profile.Provider, profile.ProviderUserID)
	}

	return user
}

// Linking modes (used by LinkingPolicy decisions).
const (
	LinkModeAutoCreate    = "auto_create"
	LinkModeEmailMatch    = "email_match"
	LinkModeExplicitOnly  = "explicit_only"
	LinkModeRejectUnknown = "reject_unknown"
)

// PolicyAutoCreate creates a new user if one does not exist.
func PolicyAutoCreate() LinkingPolicy {
	return func(ctx context.Context, lc LinkingContext) (LinkDecision, error) {
		return LinkDecision{
			Mode:                 LinkModeAutoCreate,
			AllowSignup:          true,
			AllowLinking:         true,
			RequireEmailVerified: true,
		}, nil
	}
}

// PolicyExplicitOnly only links when explicitly requested.
func PolicyExplicitOnly() LinkingPolicy {
	return func(ctx context.Context, lc LinkingContext) (LinkDecision, error) {
		return LinkDecision{
			Mode:                 LinkModeExplicitOnly,
			AllowSignup:          false,
			AllowLinking:         true,
			RequireEmailVerified: true,
		}, nil
	}
}

// PolicyEmailMatch only links when email matches a verified account.
func PolicyEmailMatch() LinkingPolicy {
	return func(ctx context.Context, lc LinkingContext) (LinkDecision, error) {
		return LinkDecision{
			Mode:                 LinkModeEmailMatch,
			AllowSignup:          false,
			AllowLinking:         true,
			RequireEmailVerified: true,
		}, nil
	}
}

// PolicyRejectUnknown rejects accounts that do not already exist.
func PolicyRejectUnknown() LinkingPolicy {
	return func(ctx context.Context, lc LinkingContext) (LinkDecision, error) {
		return LinkDecision{
			Mode:                 LinkModeRejectUnknown,
			AllowSignup:          false,
			AllowLinking:         false,
			RequireEmailVerified: true,
		}, nil
	}
}
