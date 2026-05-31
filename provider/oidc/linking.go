package oidc

import (
	"context"
	"database/sql"
	"fmt"
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

type LinkerConfig struct {
	Users         auth.Users
	Identifiers   auth.IdentifierStore
	AllowSignup   bool
	EmailFallback EmailFallbackPolicy
	DefaultRole   auth.UserRole
	ActivitySink  auth.ActivitySink
}

type DefaultIdentityLinker struct {
	users         auth.Users
	identifiers   auth.IdentifierStore
	allowSignup   bool
	emailFallback EmailFallbackPolicy
	defaultRole   auth.UserRole
	activitySink  auth.ActivitySink
}

func NewIdentityLinker(cfg LinkerConfig) (*DefaultIdentityLinker, error) {
	if cfg.Users == nil {
		return nil, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "users"})
	}
	if cfg.Identifiers == nil {
		return nil, cloneWithProvider(ErrInvalidConfig, "", map[string]any{"field": "identifiers"})
	}
	role := cfg.DefaultRole
	if role == "" {
		role = auth.RoleMember
	}
	return &DefaultIdentityLinker{
		users:         cfg.Users,
		identifiers:   cfg.Identifiers,
		allowSignup:   cfg.AllowSignup,
		emailFallback: cfg.EmailFallback,
		defaultRole:   role,
		activitySink:  cfg.ActivitySink,
	}, nil
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

	userID, err := l.identifiers.FindUserID(ctx, provider, subject)
	if err == nil && strings.TrimSpace(userID) != "" {
		user, err := l.users.GetByIdentifier(ctx, userID)
		if err != nil {
			if isNotFound(err) {
				err = duplicateSubjectError(provider, subject)
			}
			l.emit(ctx, auth.ActivityEventSSOLinkRejected, userID, identity, LinkActionRejected, err)
			return nil, LinkingDecision{Action: LinkActionRejected, UserID: userID}, err
		}
		decision := LinkingDecision{Action: LinkActionExisting, UserID: user.ID.String()}
		return auth.NewIdentityFromUser(user), decision, nil
	}
	if err != nil && !isNotFound(err) {
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, "", identity, LinkActionRejected, err)
		return nil, LinkingDecision{Action: LinkActionRejected}, err
	}

	if user, decision, linked, err := l.tryEmailFallback(ctx, identity); err != nil || linked {
		if err != nil {
			return nil, decision, err
		}
		return auth.NewIdentityFromUser(user), decision, nil
	}

	if !l.allowSignup {
		err := auth.ErrSignupDisabled
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, "", identity, LinkActionRejected, err)
		return nil, LinkingDecision{Action: LinkActionRejected}, err
	}

	user := l.userFromIdentity(identity)
	created, err := l.users.Create(ctx, user)
	if err != nil {
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, "", identity, LinkActionRejected, err)
		return nil, LinkingDecision{Action: LinkActionRejected}, err
	}
	if err := l.identifiers.Upsert(ctx, created.ID.String(), provider, subject); err != nil {
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, created.ID.String(), identity, LinkActionRejected, err)
		return nil, LinkingDecision{Action: LinkActionRejected, UserID: created.ID.String()}, err
	}
	decision := LinkingDecision{Action: LinkActionCreated, UserID: created.ID.String()}
	l.emit(ctx, auth.ActivityEventSSOLinkAutomatic, created.ID.String(), identity, LinkActionCreated, nil)
	return auth.NewIdentityFromUser(created), decision, nil
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
	if err := l.identifiers.Upsert(ctx, user.ID.String(), identity.Provider, identity.Subject); err != nil {
		decision := LinkingDecision{Action: LinkActionRejected, UserID: user.ID.String()}
		l.emit(ctx, auth.ActivityEventSSOLinkRejected, user.ID.String(), identity, LinkActionRejected, err)
		return nil, decision, false, err
	}
	decision := LinkingDecision{Action: LinkActionEmailFallback, UserID: user.ID.String()}
	l.emit(ctx, auth.ActivityEventSSOLinkAutomatic, user.ID.String(), identity, LinkActionEmailFallback, nil)
	return user, decision, true, nil
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

func (l *DefaultIdentityLinker) userFromIdentity(identity ExternalIdentity) *auth.User {
	now := time.Now()
	id := uuid.New()
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
	}).EnsureStatus()
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
	for k, v := range extra {
		metadata[k] = v
	}
	if err != nil {
		metadata["error"] = err.Error()
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
