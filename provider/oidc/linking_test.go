package oidc

import (
	"context"
	"database/sql"
	"testing"

	auth "github.com/goliatone/go-auth"
	bunrepo "github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
)

func TestIdentityLinkerResolvesExistingSubject(t *testing.T) {
	user := testUser("person@example.com")
	linker, ids, _, _ := newTestLinker(t, linkerFixtures{
		usersByID: map[string]*auth.User{user.ID.String(): user},
		subjects:  map[string]string{"oidc|subject-1": user.ID.String()},
	})

	identity, decision, err := linker.Resolve(context.Background(), externalIdentity("subject-1", "other@example.com", false))
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if identity.ID() != user.ID.String() || decision.Action != LinkActionExisting {
		t.Fatalf("unexpected resolution identity=%+v decision=%+v", identity, decision)
	}
	if len(ids.upserts) != 0 {
		t.Fatalf("subject lookup should not upsert, got %+v", ids.upserts)
	}
}

func TestIdentityLinkerCreatesNewUserWhenSignupAllowed(t *testing.T) {
	linker, ids, users, sink := newTestLinker(t, linkerFixtures{allowSignup: true})

	identity, decision, err := linker.Resolve(context.Background(), externalIdentity("subject-1", "person@example.com", true))
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if identity.ID() == "" || decision.Action != LinkActionCreated {
		t.Fatalf("unexpected created resolution identity=%+v decision=%+v", identity, decision)
	}
	if len(users.created) != 1 || len(ids.upserts) != 1 {
		t.Fatalf("expected user create and identifier upsert, created=%d upserts=%d", len(users.created), len(ids.upserts))
	}
	if len(sink.events) != 1 || sink.events[0].EventType != auth.ActivityEventSSOLinkAutomatic {
		t.Fatalf("expected automatic link event, got %+v", sink.events)
	}
}

func TestIdentityLinkerRejectsDisabledSignup(t *testing.T) {
	linker, _, _, sink := newTestLinker(t, linkerFixtures{})

	_, decision, err := linker.Resolve(context.Background(), externalIdentity("subject-1", "person@example.com", true))
	if !errorHasTextCode(err, auth.TextCodeSignupDisabled) || decision.Action != LinkActionRejected {
		t.Fatalf("expected signup disabled rejection, decision=%+v err=%v", decision, err)
	}
	if len(sink.events) != 1 || sink.events[0].EventType != auth.ActivityEventSSOLinkRejected {
		t.Fatalf("expected rejection event, got %+v", sink.events)
	}
}

func TestIdentityLinkerVerifiedEmailFallback(t *testing.T) {
	user := testUser("person@example.com")
	linker, ids, _, sink := newTestLinker(t, linkerFixtures{
		usersByEmail: map[string]*auth.User{user.Email: user},
		emailFallback: EmailFallbackPolicy{
			Enabled:              true,
			RequireVerifiedEmail: true,
		},
	})

	identity, decision, err := linker.Resolve(context.Background(), externalIdentity("subject-1", "person@example.com", true))
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if identity.ID() != user.ID.String() || decision.Action != LinkActionEmailFallback {
		t.Fatalf("unexpected fallback resolution identity=%+v decision=%+v", identity, decision)
	}
	if len(ids.upserts) != 1 {
		t.Fatalf("expected identifier upsert, got %+v", ids.upserts)
	}
	if len(sink.events) != 1 || sink.events[0].EventType != auth.ActivityEventSSOLinkAutomatic {
		t.Fatalf("expected automatic fallback event, got %+v", sink.events)
	}
}

func TestIdentityLinkerRejectsUnverifiedEmailFallback(t *testing.T) {
	user := testUser("person@example.com")
	linker, _, _, sink := newTestLinker(t, linkerFixtures{
		usersByEmail: map[string]*auth.User{user.Email: user},
		emailFallback: EmailFallbackPolicy{
			Enabled:              true,
			RequireVerifiedEmail: true,
		},
	})

	_, decision, err := linker.Resolve(context.Background(), externalIdentity("subject-1", "person@example.com", false))
	if !errorHasTextCode(err, TextCodeOIDCLinkingRejected) || decision.Action != LinkActionRejected {
		t.Fatalf("expected unverified fallback rejection, decision=%+v err=%v", decision, err)
	}
	if len(sink.events) != 1 || sink.events[0].EventType != auth.ActivityEventSSOLinkRejected {
		t.Fatalf("expected rejection event, got %+v", sink.events)
	}
}

func TestIdentityLinkerRejectsDuplicateSubjectMapping(t *testing.T) {
	linker, _, _, _ := newTestLinker(t, linkerFixtures{
		subjects: map[string]string{"oidc|subject-1": uuid.NewString()},
	})

	_, _, err := linker.Resolve(context.Background(), externalIdentity("subject-1", "person@example.com", true))
	if !errorHasTextCode(err, TextCodeOIDCDuplicateSubject) {
		t.Fatalf("expected duplicate subject error, got %v", err)
	}
}

func TestIdentityLinkerManualLinkAndUnlinkEvents(t *testing.T) {
	linker, _, _, sink := newTestLinker(t, linkerFixtures{})
	userID := uuid.NewString()
	identity := externalIdentity("subject-1", "person@example.com", true)

	linker.RecordManualLink(context.Background(), userID, identity, map[string]any{"reason": "admin"})
	linker.RecordUnlink(context.Background(), userID, identity, nil)

	if len(sink.events) != 2 {
		t.Fatalf("expected two events, got %+v", sink.events)
	}
	if sink.events[0].EventType != auth.ActivityEventSSOLinkManual || sink.events[1].EventType != auth.ActivityEventSSOUnlink {
		t.Fatalf("unexpected events: %+v", sink.events)
	}
}

func TestIdentityLinkerUnlinkDeletesIdentifierAndEmitsEvent(t *testing.T) {
	linker, ids, _, sink := newTestLinker(t, linkerFixtures{})
	userID := uuid.NewString()
	identity := externalIdentity("subject-1", "person@example.com", true)

	if err := linker.Unlink(context.Background(), userID, identity); err != nil {
		t.Fatalf("Unlink returned error: %v", err)
	}
	if len(ids.deletes) != 1 || ids.deletes[0] != userID+"|oidc|subject-1" {
		t.Fatalf("expected identifier delete, got %+v", ids.deletes)
	}
	if len(sink.events) != 1 || sink.events[0].EventType != auth.ActivityEventSSOUnlink {
		t.Fatalf("expected unlink event, got %+v", sink.events)
	}
}

type linkerFixtures struct {
	allowSignup   bool
	emailFallback EmailFallbackPolicy
	usersByID     map[string]*auth.User
	usersByEmail  map[string]*auth.User
	subjects      map[string]string
}

func newTestLinker(t *testing.T, fixtures linkerFixtures) (*DefaultIdentityLinker, *fakeIdentifierStore, *fakeUsers, *recordingSink) {
	t.Helper()
	ids := &fakeIdentifierStore{subjects: fixtures.subjects}
	users := &fakeUsers{byID: fixtures.usersByID, byEmail: fixtures.usersByEmail}
	sink := &recordingSink{}
	linker, err := NewIdentityLinker(LinkerConfig{
		Users:         users,
		Identifiers:   ids,
		AllowSignup:   fixtures.allowSignup,
		EmailFallback: fixtures.emailFallback,
		ActivitySink:  sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	return linker, ids, users, sink
}

type recordingSink struct {
	events []auth.ActivityEvent
}

func (s *recordingSink) Record(_ context.Context, event auth.ActivityEvent) error {
	s.events = append(s.events, event)
	return nil
}

func externalIdentity(subject, email string, verified bool) ExternalIdentity {
	return ExternalIdentity{
		Provider:      "oidc",
		Subject:       subject,
		Email:         email,
		EmailVerified: verified,
		GivenName:     "Test",
		FamilyName:    "Person",
	}
}

func testUser(email string) *auth.User {
	return &auth.User{
		ID:             uuid.New(),
		Email:          email,
		Username:       email,
		Role:           auth.RoleMember,
		Status:         auth.UserStatusActive,
		EmailValidated: true,
	}
}

type fakeIdentifierStore struct {
	subjects map[string]string
	upserts  []string
	deletes  []string
}

func (s *fakeIdentifierStore) FindUserID(_ context.Context, provider, identifier string) (string, error) {
	if s.subjects == nil {
		return "", bunrepo.NewRecordNotFound()
	}
	userID, ok := s.subjects[provider+"|"+identifier]
	if !ok {
		return "", bunrepo.NewRecordNotFound()
	}
	return userID, nil
}

func (s *fakeIdentifierStore) Upsert(_ context.Context, userID, provider, identifier string) error {
	s.upserts = append(s.upserts, userID+"|"+provider+"|"+identifier)
	return nil
}

func (s *fakeIdentifierStore) Delete(_ context.Context, userID, provider, identifier string) error {
	s.deletes = append(s.deletes, userID+"|"+provider+"|"+identifier)
	return nil
}

type fakeUsers struct {
	auth.Users
	byID    map[string]*auth.User
	byEmail map[string]*auth.User
	created []*auth.User
}

func (u *fakeUsers) GetByIdentifier(_ context.Context, identifier string, _ ...bunrepo.SelectCriteria) (*auth.User, error) {
	if user := u.byID[identifier]; user != nil {
		return user, nil
	}
	if user := u.byEmail[identifier]; user != nil {
		return user, nil
	}
	return nil, sql.ErrNoRows
}

func (u *fakeUsers) Create(_ context.Context, record *auth.User, _ ...bunrepo.InsertCriteria) (*auth.User, error) {
	if record.ID == uuid.Nil {
		record.ID = uuid.New()
	}
	u.created = append(u.created, record)
	return record, nil
}
