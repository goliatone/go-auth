package auth_test

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/django/v3"
	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-repository-bun"
	"github.com/goliatone/go-router"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

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

func setupTestController(_ *testing.T) (*auth.AuthController, *MockRepositoryManager, *MockUsers, *MockPasswordResets, *MockHTTPAuthenticator, router.Server[*fiber.App]) {
	mockRepo := new(MockRepositoryManager)
	mockUsers := new(MockUsers)
	mockPasswordResets := new(MockPasswordResets)
	mockHTTPAuth := new(MockHTTPAuthenticator)

	mockRepo.On("Users").Return(mockUsers)
	mockRepo.On("PasswordResets").Return(mockPasswordResets)

	engine := django.New("./testdata/views", ".html")

	adapter := router.NewFiberAdapter(func(a *fiber.App) *fiber.App {
		return fiber.New(fiber.Config{
			Views:             engine,
			PassLocalsToViews: true,
		})
	})

	controller := auth.NewAuthController(
		func(c *auth.AuthController) *auth.AuthController {
			c.Repo = mockRepo
			c.Auther = mockHTTPAuth
			c.Debug = true
			return c
		},
	)

	return controller, mockRepo, mockUsers, mockPasswordResets, mockHTTPAuth, adapter
}

func TestLoginShow(t *testing.T) {
	controller, _, _, _, _, adapter := setupTestController(t)
	r := adapter.Router()

	r.Get("/login", controller.LoginShow)

	req := httptest.NewRequest("GET", "/login", nil)
	resp, err := adapter.WrappedRouter().Test(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLoginPost_ValidCredentials(t *testing.T) {
	controller, _, _, _, mockHTTPAuth, adapter := setupTestController(t)
	r := adapter.Router()

	mockHTTPAuth.On("Login", mock.Anything, mock.MatchedBy(func(payload auth.LoginPayload) bool {
		return payload.GetIdentifier() == "user@example.com" && payload.GetPassword() == "password123"
	})).Return(nil)

	mockHTTPAuth.On("GetRedirect", mock.Anything, []string{"/"}).Return("/dashboard")

	r.Post("/login", controller.LoginPost)

	form := url.Values{}
	form.Add("identifier", "user@example.com")
	form.Add("password", "password123")
	form.Add("remember_me", "true")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := adapter.WrappedRouter().Test(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/dashboard", resp.Header.Get("Location"))

	mockHTTPAuth.AssertExpectations(t)
}

func TestLoginPost_InvalidCredentials(t *testing.T) {
	controller, _, _, _, mockHTTPAuth, adapter := setupTestController(t)
	r := adapter.Router()

	mockHTTPAuth.On("Login", mock.Anything, mock.MatchedBy(func(payload auth.LoginPayload) bool {
		return payload.GetIdentifier() == "user@example.com" && payload.GetPassword() == "wrongpassword"
	})).Return(auth.ErrMismatchedHashAndPassword)

	r.Post("/login", controller.LoginPost)

	form := url.Values{}
	form.Add("identifier", "user@example.com")
	form.Add("password", "wrongpassword")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := adapter.WrappedRouter().Test(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Authentication Error")

	mockHTTPAuth.AssertExpectations(t)
}

func TestLoginPost_InvalidForm(t *testing.T) {
	controller, _, _, _, _, adapter := setupTestController(t)
	r := adapter.Router()

	r.Post("/login", controller.LoginPost)

	form := url.Values{}

	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := adapter.WrappedRouter().Test(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "validation")
}

func TestLogout(t *testing.T) {
	controller, _, _, _, mockHTTPAuth, adapter := setupTestController(t)
	r := adapter.Router()

	mockHTTPAuth.On("Logout", mock.Anything).Return()

	r.Get("/logout", controller.LogOut)

	req := httptest.NewRequest("GET", "/logout", nil)
	resp, err := adapter.WrappedRouter().Test(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	assert.Equal(t, "/", resp.Header.Get("Location"))

	mockHTTPAuth.AssertExpectations(t)
}

func TestRegistrationShow(t *testing.T) {
	controller, _, _, _, _, adapter := setupTestController(t)
	r := adapter.Router()

	r.Get("/register", controller.RegistrationShow)

	req := httptest.NewRequest("GET", "/register", nil)
	resp, err := adapter.WrappedRouter().Test(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRegistrationCreate_Success(t *testing.T) {
	controller, mockRepo, mockUsers, _, _, adapter := setupTestController(t)
	r := adapter.Router()

	mockRepo.
		On("RunInTx", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(func(context.Context, bun.Tx) error)
			fn(context.Background(), bun.Tx{})
		}).
		Return(nil).
		Once()

	userID := uuid.New()
	user := &auth.User{
		ID:        userID,
		FirstName: "Jhon",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
		Phone:     "1234567890",
	}

	mockUsers.
		On("CreateTx", mock.Anything, mock.Anything, mock.Anything).
		Return(user, nil).
		Once()

	r.Post("/register", controller.RegistrationCreate)

	form := url.Values{}
	form.Add("first_name", "John")
	form.Add("last_name", "Doe")
	form.Add("email", "john.doe@example.com")
	form.Add("phone_number", "1234567890")
	form.Add("password", "password123456")
	form.Add("confirm_password", "password123456")

	req := httptest.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := adapter.WrappedRouter().Test(req, 2000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/", resp.Header.Get("Location"))

	/**
	* NOTE: setupTestController creates two expectations
	* for Users and PasswordRestes, the flow in
	* RegsitrationCreate never calls PR so we do here
	 */
	_ = mockRepo.PasswordResets()

	mockRepo.AssertExpectations(t)
	mockUsers.AssertExpectations(t)
}

func TestRegistrationCreate_ValidationError(t *testing.T) {
	controller, _, _, _, _, adapter := setupTestController(t)
	r := adapter.Router()

	r.Post("/register", controller.RegistrationCreate)

	form := url.Values{}
	form.Add("first_name", "John")
	form.Add("last_name", "Doe")
	form.Add("email", "invalid-email")
	form.Add("password", "short")
	form.Add("confirm_password", "different")

	req := httptest.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := adapter.WrappedRouter().Test(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "validation")
}

func TestPasswordResetGet(t *testing.T) {
	controller, _, _, _, _, adapter := setupTestController(t)
	r := adapter.Router()

	r.Get("/password-reset", controller.PasswordResetGet)

	req := httptest.NewRequest("GET", "/password-reset", nil)
	resp, err := adapter.WrappedRouter().Test(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPasswordResetPost_Success(t *testing.T) {
	controller, mockRepo, mockUsers, mockPasswordResets, _, adapter := setupTestController(t)
	r := adapter.Router()

	userID := uuid.New()
	user := &auth.User{
		ID:    userID,
		Email: "user@example.com",
	}

	mockRepo.On("Users").Return(mockUsers)
	mockUsers.On("GetByIdentifier", mock.Anything, "user@example.com").Return(user, nil)

	reset := &auth.PasswordReset{
		Email:  user.Email,
		Status: "requested",
		UserID: &user.ID,
	}

	mockPasswordResets.On("CreateTx", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(reset, nil).
		Once()

	mockRepo.On("RunInTx", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		fn := args.Get(2).(func(context.Context, bun.Tx) error)
		fn(context.Background(), bun.Tx{})
	}).Return(nil)

	r.Post("/password-reset", controller.PasswordResetPost)

	form := url.Values{}
	form.Add("email", "user@example.com")
	form.Add("stage", auth.ResetInit)

	req := httptest.NewRequest("POST", "/password-reset", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := adapter.WrappedRouter().Test(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	mockRepo.AssertExpectations(t)
	mockUsers.AssertExpectations(t)
}

func TestPasswordResetForm_Invalid(t *testing.T) {
	controller, mockRepo, _, mockPasswordResets, _, adapter := setupTestController(t)
	r := adapter.Router()

	resetID := uuid.New().String()

	mockRepo.On("PasswordResets").Return(mockPasswordResets).Once()
	mockPasswordResets.
		On("GetByID", mock.Anything, resetID, mock.Anything).
		Return(nil, repository.ErrRecordNotFound).Once()

	mockRepo.
		On("RunInTx", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			cb := args.Get(2).(func(context.Context, bun.Tx) error)
			cb(context.Background(), bun.Tx{})
		}).
		Return(nil).
		Once()

	r.Get("/password-reset/:uuid", controller.PasswordResetForm)

	req := httptest.NewRequest("GET", "/password-reset/"+resetID, nil)
	resp, err := adapter.WrappedRouter().Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `Invalid or expired password reset request`)
}

func TestPasswordResetExecute_Success(t *testing.T) {
	controller, mockRepo, mockUsers, mockPasswordResets, _, adapter := setupTestController(t)
	r := adapter.Router()

	resetID := uuid.New().String()
	resetTime := time.Now()
	userID := uuid.New()
	passwordReset := &auth.PasswordReset{
		ID:        uuid.MustParse(resetID),
		Status:    auth.ResetRequestedStatus,
		CreatedAt: &resetTime,
		UserID:    &userID,
	}

	/////////////////////////////////////////////////
	/// We are mocking the calls inside the file:
	/// command_password_reset_finalize.go
	/////////////////////////////////////////////////

	// Setup for the PasswordResets methods
	mockRepo.On("PasswordResets").Return(mockPasswordResets)
	mockPasswordResets.
		On("GetByID", mock.Anything, resetID, mock.Anything).
		Return(passwordReset, nil)
	// Expect an update call to mark the password reset as used
	mockPasswordResets.
		On("UpdateTx", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(passwordReset, nil)

	// Setup for the Users methods
	// Assuming you have a Users mock available (mockUsers) from setupTestController
	mockRepo.On("Users").Return(mockUsers)
	// Expect the RawTx call to update the user's password
	mockUsers.
		On("RawTx", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return([]*auth.User{}, nil)

	// Setup RunInTx, which wraps all these calls in a transaction
	mockRepo.
		On("RunInTx", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(func(context.Context, bun.Tx) error)
			fn(context.Background(), bun.Tx{})
		}).
		Return(nil)

	r.Post("/password-reset/:uuid", controller.PasswordResetExecute)

	form := url.Values{}
	form.Add("stage", auth.ChangingPassword)
	form.Add("password", "newpassword12345")
	form.Add("confirm_password", "newpassword12345")

	req := httptest.NewRequest("POST", "/password-reset/"+resetID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := adapter.WrappedRouter().Test(req, 2000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	mockRepo.AssertExpectations(t)
	mockPasswordResets.AssertExpectations(t)
	mockUsers.AssertExpectations(t)
}

func TestPasswordResetExecute_ValidationError(t *testing.T) {
	controller, _, _, _, _, adapter := setupTestController(t)
	r := adapter.Router()

	resetID := uuid.New().String()

	r.Post("/password-reset/:uuid", controller.PasswordResetExecute)

	form := url.Values{}
	form.Add("stage", auth.ChangingPassword)
	form.Add("password", "short")
	form.Add("confirm_password", "different")

	req := httptest.NewRequest("POST", "/password-reset/"+resetID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := adapter.WrappedRouter().Test(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "validation")

	/**
	 * NOTE: validation error means that we
	 * never get to call any of the repositories
	 */
	// mockRepo.AssertExpectations(t)
	// mockUsers.AssertExpectations(t)
}

type AuthConfig struct {
	Audience              []string `json:"audience" koanf:"audience"`
	AuthScheme            string   `json:"auth_scheme" koanf:"auth_scheme"`
	ContextKey            string   `json:"context_key" koanf:"context_key"`
	ExtendedTokenDuration int      `json:"extended_token_duration" koanf:"extended_token_duration"`
	Issuer                string   `json:"issuer" koanf:"issuer"`
	RejectedRouteDefault  string   `json:"rejected_route_default" koanf:"rejected_route_default"`
	RejectedRouteKey      string   `json:"rejected_route_key" koanf:"rejected_route_key"`
	SigningKey            string   `json:"signing_key" koanf:"signing_key"`
	SigningMethod         string   `json:"signing_method" koanf:"signing_method"`
	TokenExpiration       int      `json:"token_expiration" koanf:"token_expiration"`
	TokenLookup           string   `json:"token_lookup" koanf:"token_lookup"`
}

// Auth Getters

func (a AuthConfig) GetAudience() []string {
	return a.Audience
}

func (a AuthConfig) GetAuthScheme() string {
	return a.AuthScheme
}

func (a AuthConfig) GetContextKey() string {
	return a.ContextKey
}

func (a AuthConfig) GetExtendedTokenDuration() int {
	return a.ExtendedTokenDuration
}

func (a AuthConfig) GetIssuer() string {
	return a.Issuer
}

func (a AuthConfig) GetRejectedRouteDefault() string {
	return a.RejectedRouteDefault
}

func (a AuthConfig) GetRejectedRouteKey() string {
	return a.RejectedRouteKey
}

func (a AuthConfig) GetSigningKey() string {
	return a.SigningKey
}

func (a AuthConfig) GetSigningMethod() string {
	return a.SigningMethod
}

func (a AuthConfig) GetTokenExpiration() int {
	return a.TokenExpiration
}

func (a AuthConfig) GetTokenLookup() string {
	return a.TokenLookup
}

func TestProtectedRoutes(t *testing.T) {
	adapter := router.NewFiberAdapter(func(a *fiber.App) *fiber.App {
		return fiber.New()
	})
	r := adapter.Router()

	mockAuth := new(MockHTTPAuthenticator)

	cfg := AuthConfig{}

	errorHandler := func(c router.Context, err error) error {
		return c.Status(401).SendString("Unauthorized")
	}

	protectedMiddleware := func(router.HandlerFunc) router.HandlerFunc {
		return func(c router.Context) error {
			if c.Query("token", "") != "valid" {
				return c.Status(401).SendString("Unauthorized")
			}
			return c.Next()
		}
	}

	mockAuth.
		On("ProtectedRoute", cfg, mock.Anything).
		Return(protectedMiddleware).
		Once()

	profileHandler := func(c router.Context) error {
		return c.SendString("Profile Data")
	}

	protected := mockAuth.ProtectedRoute(cfg, errorHandler)

	r.Get("/me", profileHandler, protected)

	/**
	 * UNAUTHORIZED REQUEST
	 * No "token" parameter -> middleware block access
	 */
	req := httptest.NewRequest("GET", "/me", nil)
	resp, err := adapter.WrappedRouter().Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Unauthorized")

	/**
	 * AUTHORIZED REQUEST
	 * "token=valid" -> middleware grant access
	 */
	req = httptest.NewRequest("GET", "/me?token=valid", nil)
	resp, err = adapter.WrappedRouter().Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ = io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Profile Data")

	mockAuth.AssertExpectations(t)
}
