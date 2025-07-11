package auth_test

import (
	"context"
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
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

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
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

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
	controller, mockRepo, mockUsers, _, mockHTTPAuth, adapter := setupTestController(t)
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
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
		Phone:     "1234567890",
	}

	mockUsers.
		On("CreateTx", mock.Anything, mock.Anything, mock.Anything).
		Return(user, nil).
		Once()

	mockHTTPAuth.On("Login", mock.Anything, mock.MatchedBy(func(payload auth.LoginPayload) bool {
		return payload.GetIdentifier() == "john.doe@example.com" &&
			payload.GetPassword() == "password123456"
	})).Return(nil).Once()

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
	mockHTTPAuth.AssertExpectations(t)
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
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

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
		Return(nil, repository.NewRecordNotFound()).Once()

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
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

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
