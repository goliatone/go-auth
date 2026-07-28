package oidc

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"strings"
	"time"

	auth "github.com/goliatone/go-auth"
	bunrepo "github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
)

const (
	LinkActionExisting      = "existing_subject"
	LinkActionCreated       = "created_user"
	LinkActionEmailFallback = "email_fallback"
	LinkActionRejected      = "rejected"
)

type IdentifierBindingMode uint8

const (
	// IdentifierBindingLegacyCompatible permits mutable Upsert fallback.
	// Deprecated: hardened and provider-session flows must use an immutable or
	// transactional mode.
	IdentifierBindingLegacyCompatible IdentifierBindingMode = iota
	IdentifierBindingImmutableRequired
	IdentifierBindingTransactionalRequired
)

func (m IdentifierBindingMode) valid() bool {
	return m >= IdentifierBindingLegacyCompatible && m <= IdentifierBindingTransactionalRequired
}

// IdentityLinkerSecurityCapability lets hardened browser composition verify
// that an injected linker cannot reassign an external subject.
type IdentityLinkerSecurityCapability interface {
	IdentifierBindingMode() IdentifierBindingMode
}

type LinkerConfig struct {
	Users         auth.Users
	Identifiers   auth.IdentifierStore
	BindingMode   IdentifierBindingMode
	AllowSignup   bool
	EmailFallback EmailFallbackPolicy
	DefaultRole   auth.UserRole
	IDStrategy    IdentityIDStrategy
	UserFactory   UserFactory
	ActivitySink  auth.ActivitySink
}

// IdentityIDStrategy selects a local user ID before persistence. Strategies
// must validate provider subjects before returning an ID.
type IdentityIDStrategy interface {
	UserID(context.Context, ExternalIdentity) (uuid.UUID, error)
}

// IdentityIDStrategyFunc adapts a function to IdentityIDStrategy.
type IdentityIDStrategyFunc func(context.Context, ExternalIdentity) (uuid.UUID, error)

func (f IdentityIDStrategyFunc) UserID(ctx context.Context, identity ExternalIdentity) (uuid.UUID, error) {
	if f == nil {
		return uuid.Nil, cloneWithProvider(ErrLinkingRejected, identity.Provider, map[string]any{"cause": "identity ID strategy is unavailable"})
	}
	return f(ctx, identity)
}

// GeneratedIdentityIDStrategy preserves the historical random UUID behavior.
type GeneratedIdentityIDStrategy struct{}

func (GeneratedIdentityIDStrategy) UserID(context.Context, ExternalIdentity) (uuid.UUID, error) {
	return uuid.New(), nil
}

// ProviderSubjectUUIDIDStrategy uses a validated UUID provider subject as the
// local user ID. Provider optionally restricts the strategy to one provider.
type ProviderSubjectUUIDIDStrategy struct {
	Provider string
}

func (s ProviderSubjectUUIDIDStrategy) UserID(_ context.Context, identity ExternalIdentity) (uuid.UUID, error) {
	provider := strings.TrimSpace(identity.Provider)
	expected := strings.TrimSpace(s.Provider)
	if expected != "" && !strings.EqualFold(provider, expected) {
		return uuid.Nil, cloneWithProvider(ErrLinkingRejected, provider, map[string]any{"cause": "provider subject ID strategy mismatch"})
	}
	id, err := uuid.Parse(strings.TrimSpace(identity.Subject))
	if err != nil || id == uuid.Nil {
		return uuid.Nil, cloneWithProvider(ErrLinkingRejected, provider, map[string]any{"cause": "provider subject must be a non-zero UUID"})
	}
	return id, nil
}

// UserFactory builds a local user before create-and-bind. Hosts can use it for
// provider-specific defaults without changing the linker transaction boundary.
type UserFactory interface {
	NewUser(context.Context, ExternalIdentity, auth.UserRole) (*auth.User, error)
}

// UserFactoryFunc adapts a function to UserFactory.
type UserFactoryFunc func(context.Context, ExternalIdentity, auth.UserRole) (*auth.User, error)

func (f UserFactoryFunc) NewUser(ctx context.Context, identity ExternalIdentity, role auth.UserRole) (*auth.User, error) {
	if f == nil {
		return nil, cloneWithProvider(ErrLinkingRejected, identity.Provider, map[string]any{"cause": "user factory is unavailable"})
	}
	return f(ctx, identity, role)
}

type DefaultIdentityLinker struct {
	users         auth.Users
	identifiers   auth.IdentifierStore
	allowSignup   bool
	emailFallback EmailFallbackPolicy
	defaultRole   auth.UserRole
	idStrategy    IdentityIDStrategy
	userFactory   UserFactory
	activitySink  auth.ActivitySink
	bindingMode   IdentifierBindingMode
}

func NewIdentityLinker(cfg LinkerConfig) (*DefaultIdentityLinker, error) {
	if cfg.Users == nil {
		return nil, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "users"})
	}
	if cfg.Identifiers == nil {
		return nil, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "identifiers"})
	}
	if !cfg.BindingMode.valid() {
		return nil, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "identifier_binding_mode"})
	}
	switch cfg.BindingMode {
	case IdentifierBindingImmutableRequired:
		if _, ok := cfg.Identifiers.(auth.ImmutableIdentifierStore); !ok {
			return nil, cloneWithProvider(ErrInvalidConfig, "", map[string]any{
				"field": "identifiers", "cause": "immutable identifier binding is required",
			})
		}
		if cfg.AllowSignup {
			if _, ok := cfg.Identifiers.(auth.TransactionalIdentifierStore); !ok {
				return nil, cloneWithProvider(ErrInvalidConfig, "", map[string]any{
					"field": "identifiers", "cause": "transactional create-and-bind is required for signup",
				})
			}
		}
	case IdentifierBindingTransactionalRequired:
		if _, ok := cfg.Identifiers.(auth.TransactionalIdentifierStore); !ok {
			return nil, cloneWithProvider(ErrInvalidConfig, "", map[string]any{
				"field": "identifiers", "cause": "transactional identifier binding is required",
			})
		}
	}
	if cfg.IDStrategy != nil && cfg.UserFactory != nil {
		return nil, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "identity_creation", "cause": "ID strategy and user factory are mutually exclusive"})
	}
	role := cfg.DefaultRole
	if role == "" {
		role = auth.RoleMember
	}
	idStrategy := cfg.IDStrategy
	if idStrategy == nil {
		idStrategy = GeneratedIdentityIDStrategy{}
	}
	return &DefaultIdentityLinker{
		users:         cfg.Users,
		identifiers:   cfg.Identifiers,
		allowSignup:   cfg.AllowSignup,
		emailFallback: cfg.EmailFallback,
		defaultRole:   role,
		idStrategy:    idStrategy,
		userFactory:   cfg.UserFactory,
		activitySink:  cfg.ActivitySink,
		bindingMode:   cfg.BindingMode,
	}, nil
}

func (l *DefaultIdentityLinker) IdentifierBindingMode() IdentifierBindingMode {
	if l == nil {
		return IdentifierBindingLegacyCompatible
	}
	return l.bindingMode
}

func (l *DefaultIdentityLinker) Resolve(ctx context.Context, identity ExternalIdentity) (auth.Identity, LinkingDecision, error) {
	if l == nil || l.users == nil || l.identifiers == nil {
		return nil, LinkingDecision{Action: LinkActionRejected}, ErrLinkingRejected
	}
	provider := strings.TrimSpace(identity.Provider)
	subject := strings.TrimSpace(identity.Subject)
	if provider == "" || subject == "" {
		err := cloneWithProvider(ErrLinkingRejected, provider, map[string]any{"cause": "provider and subject are required"})
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, "", identity, LinkActionRejected, err)
		return nil, LinkingDecision{Action: LinkActionRejected}, err
	}

	user, decision, found, err := l.resolveSubject(ctx, identity, provider, subject)
	if err != nil || found {
		if err != nil {
			return nil, decision, err
		}
		return auth.NewIdentityFromUser(user), decision, nil
	}

	user, decision, found, err = l.tryEmailFallback(ctx, identity)
	if err != nil || found {
		if err != nil {
			return nil, decision, err
		}
		return auth.NewIdentityFromUser(user), decision, nil
	}

	return l.createLinkedUser(ctx, identity, provider, subject)
}

func (l *DefaultIdentityLinker) resolveSubject(ctx context.Context, identity ExternalIdentity, provider string, subject string) (*auth.User, LinkingDecision, bool, error) {
	userID, err := l.identifiers.FindUserID(ctx, provider, subject)
	if err != nil {
		if isNotFound(err) {
			return nil, LinkingDecision{}, false, nil
		}
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, "", identity, LinkActionRejected, err)
		return nil, LinkingDecision{Action: LinkActionRejected}, false, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, LinkingDecision{}, false, nil
	}

	user, err := l.users.GetByIdentifier(ctx, userID)
	if err != nil {
		if isNotFound(err) {
			err = duplicateSubjectError(provider, subject)
		}
		decision := LinkingDecision{Action: LinkActionRejected, UserID: userID}
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, userID, identity, LinkActionRejected, err)
		return nil, decision, false, err
	}
	decision := LinkingDecision{Action: LinkActionExisting, UserID: user.ID.String()}
	return user, decision, true, nil
}

func (l *DefaultIdentityLinker) tryEmailFallback(ctx context.Context, identity ExternalIdentity) (*auth.User, LinkingDecision, bool, error) {
	email := strings.TrimSpace(identity.Email)
	if email == "" {
		return nil, LinkingDecision{}, false, nil
	}
	user, err := l.users.GetByIdentifier(ctx, email)
	if err != nil {
		if isNotFound(err) {
			return nil, LinkingDecision{}, false, nil
		}
		decision := LinkingDecision{Action: LinkActionRejected}
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, "", identity, LinkActionRejected, err)
		return nil, decision, false, err
	}
	if user == nil {
		return nil, LinkingDecision{}, false, nil
	}
	if !l.emailFallback.Enabled || (l.emailFallback.RequireVerifiedEmail && !identity.EmailVerified) {
		err := cloneWithProvider(ErrLinkingRejected, identity.Provider, map[string]any{
			"cause":          "email fallback rejected",
			"email_verified": identity.EmailVerified,
		})
		decision := LinkingDecision{Action: LinkActionRejected, UserID: user.ID.String()}
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, user.ID.String(), identity, LinkActionRejected, err)
		return nil, decision, false, err
	}
	bindErr := l.bindIdentifier(ctx, user.ID.String(), identity.Provider, identity.Subject)
	if bindErr != nil {
		decision := LinkingDecision{Action: LinkActionRejected, UserID: user.ID.String()}
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, user.ID.String(), identity, LinkActionRejected, bindErr)
		return nil, decision, false, bindErr
	}
	decision := LinkingDecision{Action: LinkActionEmailFallback, UserID: user.ID.String()}
	l.emit(ctx, auth.ActivityEventSSOLinkAutomatic, user.ID.String(), identity, LinkActionEmailFallback, nil)
	return user, decision, true, nil
}

func (l *DefaultIdentityLinker) createLinkedUser(ctx context.Context, identity ExternalIdentity, provider string, subject string) (auth.Identity, LinkingDecision, error) {
	if !l.allowSignup {
		err := auth.ErrSignupDisabled
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, "", identity, LinkActionRejected, err)
		return nil, LinkingDecision{Action: LinkActionRejected}, err
	}

	user, err := l.userFromIdentity(ctx, identity)
	if err != nil {
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, "", identity, LinkActionRejected, err)
		return nil, LinkingDecision{Action: LinkActionRejected}, err
	}
	created, err := l.persistLinkedUser(ctx, user, provider, subject)
	if err != nil {
		if winner, decision, found, resolveErr := l.resolveSubject(ctx, identity, provider, subject); resolveErr == nil && found {
			return auth.NewIdentityFromUser(winner), decision, nil
		}
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, "", identity, LinkActionRejected, err)
		return nil, LinkingDecision{Action: LinkActionRejected}, err
	}
	decision := LinkingDecision{Action: LinkActionCreated, UserID: created.ID.String()}
	l.emit(ctx, auth.ActivityEventSSOLinkAutomatic, created.ID.String(), identity, LinkActionCreated, nil)
	return auth.NewIdentityFromUser(created), decision, nil
}

func (l *DefaultIdentityLinker) persistLinkedUser(
	ctx context.Context,
	user *auth.User,
	provider string,
	subject string,
) (*auth.User, error) {
	if transactional, ok := l.identifiers.(auth.TransactionalIdentifierStore); ok {
		return transactional.CreateUserAndBind(ctx, l.users, user, provider, subject)
	}
	created, err := l.users.Create(ctx, user)
	if err != nil {
		return nil, err
	}
	if bindErr := l.bindIdentifier(ctx, created.ID.String(), provider, subject); bindErr != nil {
		if cleanupErr := l.users.Delete(ctx, created); cleanupErr != nil {
			return nil, fmt.Errorf("%w; cleanup failed: %v", bindErr, cleanupErr)
		}
		return nil, bindErr
	}
	return created, nil
}

func (l *DefaultIdentityLinker) bindIdentifier(
	ctx context.Context,
	userID, provider, identifier string,
) error {
	if immutable, ok := l.identifiers.(auth.ImmutableIdentifierStore); ok {
		return immutable.Bind(ctx, userID, provider, identifier)
	}
	if l.bindingMode != IdentifierBindingLegacyCompatible {
		return cloneWithProvider(ErrLinkingRejected, provider, map[string]any{
			"cause": "immutable identifier binding is unavailable",
		})
	}
	return l.identifiers.Upsert(ctx, userID, provider, identifier)
}

func (l *DefaultIdentityLinker) RecordManualLink(ctx context.Context, userID string, identity ExternalIdentity, metadata map[string]any) {
	l.emitWithMetadata(ctx, auth.ActivityEventSSOLinkManual, userID, identity, "manual_link", nil, metadata)
}

func (l *DefaultIdentityLinker) Unlink(ctx context.Context, userID string, identity ExternalIdentity) error {
	if l == nil || l.identifiers == nil {
		return ErrLinkingRejected
	}
	userID = strings.TrimSpace(userID)
	if userID == "" || strings.TrimSpace(identity.Provider) == "" || strings.TrimSpace(identity.Subject) == "" {
		err := cloneWithProvider(ErrLinkingRejected, identity.Provider, map[string]any{"cause": "user, provider, and subject are required"})
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, userID, identity, LinkActionRejected, err)
		return err
	}
	if err := l.identifiers.Delete(ctx, userID, identity.Provider, identity.Subject); err != nil {
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, userID, identity, LinkActionRejected, err)
		return err
	}
	l.RecordUnlink(ctx, userID, identity, nil)
	return nil
}

func (l *DefaultIdentityLinker) RecordUnlink(ctx context.Context, userID string, identity ExternalIdentity, metadata map[string]any) {
	l.emitWithMetadata(ctx, auth.ActivityEventSSOUnlink, userID, identity, "unlink", nil, metadata)
}

func (l *DefaultIdentityLinker) userFromIdentity(ctx context.Context, identity ExternalIdentity) (*auth.User, error) {
	if l.userFactory != nil {
		user, err := l.userFactory.NewUser(ctx, identity, l.defaultRole)
		if err != nil {
			return nil, err
		}
		if user == nil || user.ID == uuid.Nil {
			return nil, cloneWithProvider(ErrLinkingRejected, identity.Provider, map[string]any{"cause": "user factory returned an invalid user"})
		}
		return user.EnsureStatus(), nil
	}
	id, err := l.idStrategy.UserID(ctx, identity)
	if err != nil {
		return nil, err
	}
	if id == uuid.Nil {
		return nil, cloneWithProvider(ErrLinkingRejected, identity.Provider, map[string]any{"cause": "identity ID strategy returned an empty UUID"})
	}
	now := time.Now()
	email := strings.TrimSpace(identity.Email)
	username := email
	if username == "" {
		username = strings.TrimSpace(identity.Nickname)
	}
	if username == "" {
		username = strings.NewReplacer("|", "-", ":", "-").Replace(identity.Subject)
	}
	return (&auth.User{
		ID:             id,
		Role:           l.defaultRole,
		Status:         auth.UserStatusActive,
		FirstName:      identity.GivenName,
		LastName:       identity.FamilyName,
		Username:       username,
		Email:          email,
		ProfilePicture: identity.Picture,
		EmailValidated: identity.EmailVerified,
		Metadata: map[string]any{
			"sso_provider": identity.Provider,
			"sso_subject":  identity.Subject,
		},
		CreatedAt: &now,
		UpdatedAt: &now,
	}).EnsureStatus(), nil
}

func (l *DefaultIdentityLinker) emit(ctx context.Context, eventType auth.ActivityEventType, userID string, identity ExternalIdentity, action string, err error) {
	l.emitWithMetadata(ctx, eventType, userID, identity, action, err, nil)
}

func (l *DefaultIdentityLinker) emitWithMetadata(ctx context.Context, eventType auth.ActivityEventType, userID string, identity ExternalIdentity, action string, err error, extra map[string]any) {
	if l == nil || l.activitySink == nil {
		return
	}
	metadata := map[string]any{
		"provider": identity.Provider,
		"subject":  identity.Subject,
		"action":   action,
	}
	maps.Copy(metadata, extra)
	if err != nil {
		metadata["error"] = "identity operation failed"
	}
	_ = l.activitySink.Record(ctx, auth.ActivityEvent{
		EventType: eventType,
		Actor:     auth.ActorRef{ID: userID, Type: "user"},
		UserID:    userID,
		Metadata:  metadata,
	})
}

func isNotFound(err error) bool {
	return err == sql.ErrNoRows || bunrepo.IsRecordNotFound(err)
}

func duplicateSubjectError(provider, subject string) error {
	return cloneWithProvider(ErrDuplicateSubject, provider, map[string]any{
		"subject": subject,
		"cause":   fmt.Sprintf("duplicate subject %s", subject),
	})
}
