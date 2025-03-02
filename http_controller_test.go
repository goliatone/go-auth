package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-router"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockHTTPAuthenticator implements HTTPAuthenticator
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

func (m *MockHTTPAuthenticator) ProtectedRoute(cfg auth.Config, errorHandler func(router.Context, error) error) router.MiddlewareFunc {
	args := m.Called(cfg, errorHandler)
	return args.Get(0).(router.MiddlewareFunc)
}

func (m *MockHTTPAuthenticator) MakeClientRouteAuthErrorHandler(optionalAuth bool) func(c router.Context, err error) error {
	args := m.Called(optionalAuth)
	return args.Get(0).(func(c router.Context, err error) error)
}

func (m *MockHTTPAuthenticator) Impersonate(c router.Context, identifier string) error {
	args := m.Called(c, identifier)
	return args.Error(0)
}

// MockRepoManager implements RepositoryManager
type MockRepoManager struct {
	mock.Mock
}

func (m *MockRepoManager) Validate() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockRepoManager) MustValidate() {
	m.Called()
}

func (m *MockRepoManager) RunInTx(ctx context.Context, opts any, f func(ctx context.Context, tx any) error) error {
	args := m.Called(ctx, opts, f)
	return args.Error(0)
}

func (m *MockRepoManager) Users() auth.Users {
	args := m.Called()
	return args.Get(0).(auth.Users)
}

func (m *MockRepoManager) PasswordResets() any {
	args := m.Called()
	return args.Get(0)
}

// MockUsers implements Users interface
type MockUsers struct {
	mock.Mock
}

func (m *MockUsers) Raw(ctx context.Context, sql string, args ...any) ([]*auth.User, error) {
	mockArgs := m.Called(ctx, sql, args)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).([]*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) RawTx(ctx context.Context, tx any, sql string, args ...any) ([]*auth.User, error) {
	mockArgs := m.Called(ctx, tx, sql, args)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).([]*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) Get(ctx context.Context, criteria ...any) (*auth.User, error) {
	mockArgs := m.Called(ctx, criteria)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) GetByID(ctx context.Context, id string, criteria ...any) (*auth.User, error) {
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

func (m *MockUsers) GetByIdentifierTx(ctx context.Context, tx any, identifier string) (*auth.User, error) {
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

func (m *MockUsers) TrackAttemptedLoginTx(ctx context.Context, tx any, user *auth.User) error {
	args := m.Called(ctx, tx, user)
	return args.Error(0)
}

func (m *MockUsers) TrackSucccessfulLogin(ctx context.Context, user *auth.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUsers) TrackSucccessfulLoginTx(ctx context.Context, tx any, user *auth.User) error {
	args := m.Called(ctx, tx, user)
	return args.Error(0)
}

func (m *MockUsers) Register(ctx context.Context, user *auth.User) (*auth.User, error) {
	mockArgs := m.Called(ctx, user)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) RegisterTx(ctx context.Context, tx any, user *auth.User) (*auth.User, error) {
	mockArgs := m.Called(ctx, tx, user)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) GetOrRegisterTx(ctx context.Context, tx any, record *auth.User) (*auth.User, error) {
	mockArgs := m.Called(ctx, tx, record)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) CreateTx(ctx context.Context, tx any, record *auth.User) (*auth.User, error) {
	mockArgs := m.Called(ctx, tx, record)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) GetOrCreate(ctx context.Context, record *auth.User) (*auth.User, error) {
	mockArgs := m.Called(ctx, record)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) GetOrCreateTx(ctx context.Context, tx any, record *auth.User) (*auth.User, error) {
	mockArgs := m.Called(ctx, tx, record)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) Update(ctx context.Context, record *auth.User, criteria ...any) (*auth.User, error) {
	mockArgs := m.Called(ctx, record, criteria)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) UpdateTx(ctx context.Context, tx any, record *auth.User, criteria ...any) (*auth.User, error) {
	mockArgs := m.Called(ctx, tx, record, criteria)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) Upsert(ctx context.Context, record *auth.User, criteria ...any) (*auth.User, error) {
	mockArgs := m.Called(ctx, record, criteria)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) UpsertTx(ctx context.Context, tx any, record *auth.User, criteria ...any) (*auth.User, error) {
	mockArgs := m.Called(ctx, tx, record, criteria)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(*auth.User), mockArgs.Error(1)
}

func (m *MockUsers) ResetPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	args := m.Called(ctx, id, passwordHash)
	return args.Error(0)
}

func (m *MockUsers) ResetPasswordTx(ctx context.Context, tx any, id uuid.UUID, passwordHash string) error {
	args := m.Called(ctx, tx, id, passwordHash)
	return args.Error(0)
}

func setupFiberTest() (*fiber.App, *httptest.Server) {
	app := fiber.New()

	app.Get("/render-test", func(c *fiber.Ctx) error {
		return c.SendString("Render Test")
	})

	return app, httptest.NewServer(app.Handler())
}

// Helper to create a fiber context for testing
func createFiberTestContext(app *fiber.App, method, path string, body url.Values) (*fiber.Ctx, error) {
	var req *http.Request
	var err error

	if body != nil {
		req, err = http.NewRequest(
			method,
			path,
			strings.NewReader(body.Encode()),
		)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest(method, path, nil)
		if err != nil {
			return nil, err
		}
	}

	return app.Test(req)
}

func TestAuthControllerLoginPost(t *testing.T) {
	app, server := setupFiberTest()
	defer server.Close()

	mockRepo := new(MockRepoManager)
	mockUsers := new(MockUsers)
	mockHTTPAuth := new(MockHTTPAuthenticator)

	mockRepo.On("Users").Return(mockUsers)
	mockRepo.On("Validate").Return(nil)

	controller := auth.NewAuthController(
		func(c *auth.AuthController) *auth.AuthController {
			c.Repo = mockRepo
			c.Auther = mockHTTPAuth
			c.Debug = true
			return c
		},
	)

	// Register login route
	app.Post("/login", controller.LoginPost)

	t.Run("Successful login", func(t *testing.T) {
		// Setup form data
		form := url.Values{}
		form.Add("identifier", "test@example.com")
		form.Add("password", "password123")

		// Setup HTTP Auth expectations
		mockHTTPAuth.On("Login", mock.Anything, mock.MatchedBy(func(p auth.LoginPayload) bool {
			return p.GetIdentifier() == "test@example.com" &&
				p.GetPassword() == "password123"
		})).Return(nil).Once()

		mockHTTPAuth.On("GetRedirect", mock.Anything, []string{"/"}).Return("/dashboard").Once()

		// Make request
		resp, err := http.PostForm(server.URL+"/login", form)
		assert.NoError(t, err)

		// Assert redirect on success
		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Equal(t, "/dashboard", resp.Header.Get("Location"))

		// Verify expectations
		mockHTTPAuth.AssertExpectations(t)
	})

	t.Run("Invalid login credentials", func(t *testing.T) {
		// Setup form data with invalid credentials
		form := url.Values{}
		form.Add("identifier", "invalid@example.com")
		form.Add("password", "wrongpassword")

		// Setup HTTP Auth expectations - login fails
		mockHTTPAuth.On("Login", mock.Anything, mock.MatchedBy(func(p auth.LoginPayload) bool {
			return p.GetIdentifier() == "invalid@example.com" &&
				p.GetPassword() == "wrongpassword"
		})).Return(errors.New("authentication failed")).Once()

		// Make request
		resp, err := http.PostForm(server.URL+"/login", form)
		assert.NoError(t, err)

		// Should not redirect on failure, should render login page with errors
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify expectations
		mockHTTPAuth.AssertExpectations(t)
	})

	t.Run("Invalid form data", func(t *testing.T) {
		// Setup invalid form data (missing password)
		form := url.Values{}
		form.Add("identifier", "test@example.com")
		// No password

		// Make request
		resp, err := http.PostForm(server.URL+"/login", form)
		assert.NoError(t, err)

		// Should not redirect, should render login page with validation errors
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
