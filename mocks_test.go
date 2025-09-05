package auth_test

import (
	"context"
	"database/sql"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-repository-bun"
	"github.com/goliatone/go-router"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/uptrace/bun"
)

// ////////////////////////////////////////////////////////////////////
// MockIdentityProvider is a mock of the IdentityProvider interface
// ////////////////////////////////////////////////////////////////////
type MockIdentityProvider struct {
	mock.Mock
}

func (m *MockIdentityProvider) VerifyIdentity(ctx context.Context, identifier, password string) (auth.Identity, error) {
	args := m.Called(ctx, identifier, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(auth.Identity), args.Error(1)
}

func (m *MockIdentityProvider) FindIdentityByIdentifier(ctx context.Context, identifier string) (auth.Identity, error) {
	args := m.Called(ctx, identifier)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(auth.Identity), args.Error(1)
}

// ////////////////////////////////////////////////////////////////////
// MockConfig for testing authenticator
// ////////////////////////////////////////////////////////////////////
type MockConfig struct {
	mock.Mock
}

func (m *MockConfig) GetSigningKey() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetSigningMethod() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetContextKey() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetTokenExpiration() int {
	args := m.Called()
	return args.Int(0)
}

func (m *MockConfig) GetExtendedTokenDuration() int {
	args := m.Called()
	return args.Int(0)
}

func (m *MockConfig) GetTokenLookup() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetAuthScheme() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetIssuer() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetAudience() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockConfig) GetRejectedRouteKey() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConfig) GetRejectedRouteDefault() string {
	args := m.Called()
	return args.String(0)
}

// ////////////////////////////////////////////////////////////////////
// MockAuthenticator implements auth.Authenticator
// ////////////////////////////////////////////////////////////////////
type MockAuthenticator struct {
	mock.Mock
}

func (m *MockAuthenticator) Login(ctx context.Context, identifier, password string) (string, error) {
	args := m.Called(ctx, identifier, password)
	return args.String(0), args.Error(1)
}

func (m *MockAuthenticator) Impersonate(ctx context.Context, identifier string) (string, error) {
	args := m.Called(ctx, identifier)
	return args.String(0), args.Error(1)
}

func (m *MockAuthenticator) SessionFromToken(token string) (auth.Session, error) {
	args := m.Called(token)
	return args.Get(0).(auth.Session), args.Error(1)
}

func (m *MockAuthenticator) IdentityFromSession(ctx context.Context, session auth.Session) (auth.Identity, error) {
	args := m.Called(ctx, session)
	return args.Get(0).(auth.Identity), args.Error(1)
}

// ////////////////////////////////////////////////////////////////////
// MockLoginPayload implements auth.LoginPayload
// ////////////////////////////////////////////////////////////////////
type MockLoginPayload struct {
	Identifier      string
	Password        string
	ExtendedSession bool
}

func (m MockLoginPayload) GetIdentifier() string {
	return m.Identifier
}

func (m MockLoginPayload) GetPassword() string {
	return m.Password
}

func (m MockLoginPayload) GetExtendedSession() bool {
	return m.ExtendedSession
}

// ////////////////////////////////////////////////////////////////////
// MockHTTPAuthenticator
// ////////////////////////////////////////////////////////////////////
type MockHTTPAuthenticator struct {
	mock.Mock
}

func (m *MockHTTPAuthenticator) Login(c router.Context, payload auth.LoginPayload) error {
	args := m.Called(c, payload)
	return args.Error(0)
}

func (m *MockHTTPAuthenticator) Logout(c router.Context) {
	m.Called(c)
}

func (m *MockHTTPAuthenticator) SetRedirect(c router.Context) {
	m.Called(c)
}

func (m *MockHTTPAuthenticator) GetRedirect(c router.Context, def ...string) string {
	args := m.Called(c, def)
	return args.String(0)
}

func (m *MockHTTPAuthenticator) GetRedirectOrDefault(c router.Context) string {
	args := m.Called(c)
	return args.String(0)
}

func (m *MockHTTPAuthenticator) MakeClientRouteAuthErrorHandler(optionalAuth bool) func(c router.Context, err error) error {
	args := m.Called(optionalAuth)
	return args.Get(0).(func(c router.Context, err error) error)
}

func (m *MockHTTPAuthenticator) ProtectedRoute(cfg auth.Config, errorHandler func(router.Context, error) error) router.MiddlewareFunc {
	args := m.Called(cfg, errorHandler)
	return args.Get(0).(func(router.HandlerFunc) router.HandlerFunc)
}

func (m *MockHTTPAuthenticator) Impersonate(c router.Context, identifier string) error {
	args := m.Called(c, identifier)
	return args.Error(0)
}

// ////////////////////////////////////////////////////////////////////
// MockRepositoryManager
// ////////////////////////////////////////////////////////////////////
type MockRepositoryManager struct {
	mock.Mock
}

func (m *MockRepositoryManager) Validate() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockRepositoryManager) MustValidate() {
	m.Called()
}

func (m *MockRepositoryManager) RunInTx(ctx context.Context, opts *sql.TxOptions, f func(context.Context, bun.Tx) error) error {
	args := m.Called(ctx, opts, f)
	return args.Error(0)
}

func (m *MockRepositoryManager) Users() auth.Users {
	args := m.Called()
	return args.Get(0).(auth.Users)
}

func (m *MockRepositoryManager) PasswordResets() repository.Repository[*auth.PasswordReset] {
	args := m.Called()
	return args.Get(0).(repository.Repository[*auth.PasswordReset])
}

// ////////////////////////////////////////////////////////////////////
// MockUsers
// ////////////////////////////////////////////////////////////////////
type MockUsers struct {
	mock.Mock
}

func (m *MockUsers) Raw(ctx context.Context, sql string, args ...any) ([]*auth.User, error) {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).([]*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) RawTx(ctx context.Context, tx bun.IDB, sql string, args ...any) ([]*auth.User, error) {
	mockArgs := m.Called(ctx, tx, sql, args)
	return mockArgs.Get(0).([]*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) Get(ctx context.Context, criteria ...repository.SelectCriteria) (*auth.User, error) {
	mockArgs := m.Called(ctx, criteria)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) GetByID(ctx context.Context, id string, criteria ...repository.SelectCriteria) (*auth.User, error) {
	mockArgs := m.Called(ctx, id, criteria)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) GetByIdentifier(ctx context.Context, identifier string) (*auth.User, error) {
	mockArgs := m.Called(ctx, identifier)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) GetByIdentifierTx(ctx context.Context, tx bun.IDB, identifier string) (*auth.User, error) {
	mockArgs := m.Called(ctx, tx, identifier)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) TrackAttemptedLogin(ctx context.Context, user *auth.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUsers) TrackAttemptedLoginTx(ctx context.Context, tx bun.IDB, user *auth.User) error {
	args := m.Called(ctx, tx, user)
	return args.Error(0)
}

func (m *MockUsers) TrackSucccessfulLogin(ctx context.Context, user *auth.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUsers) TrackSucccessfulLoginTx(ctx context.Context, tx bun.IDB, user *auth.User) error {
	args := m.Called(ctx, tx, user)
	return args.Error(0)
}

func (m *MockUsers) Register(ctx context.Context, user *auth.User) (*auth.User, error) {
	mockArgs := m.Called(ctx, user)
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) RegisterTx(ctx context.Context, tx bun.IDB, user *auth.User) (*auth.User, error) {
	mockArgs := m.Called(ctx, tx, user)
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) GetOrRegisterTx(ctx context.Context, tx bun.IDB, record *auth.User) (*auth.User, error) {
	mockArgs := m.Called(ctx, tx, record)
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) CreateTx(ctx context.Context, tx bun.IDB, record *auth.User) (*auth.User, error) {
	mockArgs := m.Called(ctx, tx, record)
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) GetOrCreate(ctx context.Context, record *auth.User) (*auth.User, error) {
	mockArgs := m.Called(ctx, record)
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) GetOrCreateTx(ctx context.Context, tx bun.IDB, record *auth.User) (*auth.User, error) {
	mockArgs := m.Called(ctx, tx, record)
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) Update(ctx context.Context, record *auth.User, criteria ...repository.UpdateCriteria) (*auth.User, error) {
	mockArgs := m.Called(ctx, record, criteria)
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) UpdateTx(ctx context.Context, tx bun.IDB, record *auth.User, criteria ...repository.UpdateCriteria) (*auth.User, error) {
	mockArgs := m.Called(ctx, tx, record, criteria)
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) Upsert(ctx context.Context, record *auth.User, criteria ...repository.UpdateCriteria) (*auth.User, error) {
	mockArgs := m.Called(ctx, record, criteria)
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) UpsertTx(ctx context.Context, tx bun.IDB, record *auth.User, criteria ...repository.UpdateCriteria) (*auth.User, error) {
	mockArgs := m.Called(ctx, tx, record, criteria)
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) ResetPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	args := m.Called(ctx, id, passwordHash)
	return args.Error(0)
}

func (m *MockUsers) ResetPasswordTx(ctx context.Context, tx bun.IDB, id uuid.UUID, passwordHash string) error {
	args := m.Called(ctx, tx, id, passwordHash)
	return args.Error(0)
}

// ////////////////////////////////////////////////////////////////////
// MockPasswordResets
// ////////////////////////////////////////////////////////////////////
type MockPasswordResets struct {
	mock.Mock
	count int
}

func (m *MockPasswordResets) Raw(ctx context.Context, sql string, args ...any) ([]*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).([]*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) RawTx(ctx context.Context, tx bun.IDB, sql string, args ...any) ([]*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, tx, sql, args)
	return mockArgs.Get(0).([]*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) Get(ctx context.Context, criteria ...repository.SelectCriteria) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, criteria)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) GetTx(ctx context.Context, tx bun.IDB, criteria ...repository.SelectCriteria) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, tx, criteria)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) GetByID(ctx context.Context, id string, criteria ...repository.SelectCriteria) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, id, criteria)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) GetByIDTx(ctx context.Context, tx bun.IDB, id string, criteria ...repository.SelectCriteria) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, tx, id, criteria)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) List(ctx context.Context, criteria ...repository.SelectCriteria) ([]*auth.PasswordReset, int, error) {
	mockArgs := m.Called(ctx, criteria)
	records := mockArgs.Get(0).([]*auth.PasswordReset)
	return records, m.count, mockArgs.Error(2)
}

func (m *MockPasswordResets) ListTx(ctx context.Context, tx bun.IDB, criteria ...repository.SelectCriteria) ([]*auth.PasswordReset, int, error) {
	mockArgs := m.Called(ctx, tx, criteria)
	records := mockArgs.Get(0).([]*auth.PasswordReset)
	return records, m.count, mockArgs.Error(2)
}

func (m *MockPasswordResets) Count(ctx context.Context, criteria ...repository.SelectCriteria) (int, error) {
	mockArgs := m.Called(ctx, criteria)
	return m.count, mockArgs.Error(1)
}

func (m *MockPasswordResets) CountTx(ctx context.Context, tx bun.IDB, criteria ...repository.SelectCriteria) (int, error) {
	mockArgs := m.Called(ctx, tx, criteria)
	return m.count, mockArgs.Error(1)
}

func (m *MockPasswordResets) Create(ctx context.Context, record *auth.PasswordReset, criteria ...repository.InsertCriteria) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, record, criteria)
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) CreateTx(ctx context.Context, tx bun.IDB, record *auth.PasswordReset, criteria ...repository.InsertCriteria) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, tx, record, criteria)
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) CreateMany(ctx context.Context, records []*auth.PasswordReset, criteria ...repository.InsertCriteria) ([]*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, records, criteria)
	return mockArgs.Get(0).([]*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) CreateManyTx(ctx context.Context, tx bun.IDB, records []*auth.PasswordReset, criteria ...repository.InsertCriteria) ([]*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, tx, records, criteria)
	return mockArgs.Get(0).([]*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) GetOrCreate(ctx context.Context, record *auth.PasswordReset) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, record)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) GetOrCreateTx(ctx context.Context, tx bun.IDB, record *auth.PasswordReset) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, tx, record)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) GetByIdentifier(ctx context.Context, identifier string, criteria ...repository.SelectCriteria) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, identifier, criteria)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) GetByIdentifierTx(ctx context.Context, tx bun.IDB, identifier string, criteria ...repository.SelectCriteria) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, tx, identifier, criteria)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) Update(ctx context.Context, record *auth.PasswordReset, criteria ...repository.UpdateCriteria) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, record, criteria)
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) UpdateTx(ctx context.Context, tx bun.IDB, record *auth.PasswordReset, criteria ...repository.UpdateCriteria) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, tx, record, criteria)
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) UpdateMany(ctx context.Context, records []*auth.PasswordReset, criteria ...repository.UpdateCriteria) ([]*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, records, criteria)
	return mockArgs.Get(0).([]*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) UpdateManyTx(ctx context.Context, tx bun.IDB, records []*auth.PasswordReset, criteria ...repository.UpdateCriteria) ([]*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, tx, records, criteria)
	return mockArgs.Get(0).([]*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) Upsert(ctx context.Context, record *auth.PasswordReset, criteria ...repository.UpdateCriteria) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, record, criteria)
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) UpsertTx(ctx context.Context, tx bun.IDB, record *auth.PasswordReset, criteria ...repository.UpdateCriteria) (*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, tx, record, criteria)
	return mockArgs.Get(0).(*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) UpsertMany(ctx context.Context, records []*auth.PasswordReset, criteria ...repository.UpdateCriteria) ([]*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, records, criteria)
	return mockArgs.Get(0).([]*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) UpsertManyTx(ctx context.Context, tx bun.IDB, records []*auth.PasswordReset, criteria ...repository.UpdateCriteria) ([]*auth.PasswordReset, error) {
	mockArgs := m.Called(ctx, tx, records, criteria)
	return mockArgs.Get(0).([]*auth.PasswordReset), mockArgs.Error(1)
}

func (m *MockPasswordResets) Delete(ctx context.Context, record *auth.PasswordReset) error {
	mockArgs := m.Called(ctx, record)
	return mockArgs.Error(0)
}

func (m *MockPasswordResets) DeleteTx(ctx context.Context, tx bun.IDB, record *auth.PasswordReset) error {
	mockArgs := m.Called(ctx, tx, record)
	return mockArgs.Error(0)
}

func (m *MockPasswordResets) DeleteMany(ctx context.Context, criteria ...repository.DeleteCriteria) error {
	mockArgs := m.Called(ctx, criteria)
	return mockArgs.Error(0)
}

func (m *MockPasswordResets) DeleteManyTx(ctx context.Context, tx bun.IDB, criteria ...repository.DeleteCriteria) error {
	mockArgs := m.Called(ctx, tx, criteria)
	return mockArgs.Error(0)
}

func (m *MockPasswordResets) DeleteWhere(ctx context.Context, criteria ...repository.DeleteCriteria) error {
	mockArgs := m.Called(ctx, criteria)
	return mockArgs.Error(0)
}

func (m *MockPasswordResets) DeleteWhereTx(ctx context.Context, tx bun.IDB, criteria ...repository.DeleteCriteria) error {
	mockArgs := m.Called(ctx, tx, criteria)
	return mockArgs.Error(0)
}

func (m *MockPasswordResets) ForceDelete(ctx context.Context, record *auth.PasswordReset) error {
	mockArgs := m.Called(ctx, record)
	return mockArgs.Error(0)
}

func (m *MockPasswordResets) ForceDeleteTx(ctx context.Context, tx bun.IDB, record *auth.PasswordReset) error {
	mockArgs := m.Called(ctx, tx, record)
	return mockArgs.Error(0)
}

func (m *MockPasswordResets) Handlers() repository.ModelHandlers[*auth.PasswordReset] {
	mockArgs := m.Called()
	return mockArgs.Get(0).(repository.ModelHandlers[*auth.PasswordReset])
}

// ////////////////////////////////////////////////////////////////////
// MockUserTracker implements UserTracker
// ////////////////////////////////////////////////////////////////////
type MockUserTracker struct {
	mock.Mock
}

func (m *MockUserTracker) GetByIdentifier(ctx context.Context, identifier string) (*auth.User, error) {
	args := m.Called(ctx, identifier)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.User), args.Error(1)
}

func (m *MockUserTracker) TrackAttemptedLogin(ctx context.Context, user *auth.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserTracker) TrackSucccessfulLogin(ctx context.Context, user *auth.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// ////////////////////////////////////////////////////////////////////
// MockResourceRoleProvider implements auth.ResourceRoleProvider
// ////////////////////////////////////////////////////////////////////
type MockResourceRoleProvider struct {
	mock.Mock
}

func (m *MockResourceRoleProvider) FindResourceRoles(ctx context.Context, identity auth.Identity) (map[string]string, error) {
	args := m.Called(ctx, identity)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]string), args.Error(1)
}
