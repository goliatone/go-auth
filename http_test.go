package auth_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/middleware/jwtware"
	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPAuthenticator(t *testing.T) {
	mockAuth := new(MockAuthenticator)
	mockConfig := new(MockConfig)

	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetExtendedTokenDuration").Return(48)

	httpAuth, err := auth.NewHTTPAuthenticator(mockAuth, mockConfig)

	require.NoError(t, err)
	assert.NotNil(t, httpAuth)

	mockConfig.AssertExpectations(t)
}

func TestRouteAuthenticator_Login(t *testing.T) {
	mockAuth := new(MockAuthenticator)
	mockConfig := new(MockConfig)
	mockCtx := new(MockContext)

	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetExtendedTokenDuration").Return(48)
	mockConfig.On("GetContextKey").Return("jwt")

	mockAuth.On("Login", mock.Anything, "user@example.com", "password123").Return("valid.jwt.token", nil)

	mockCtx.On("Context").Return(context.Background())
	mockCtx.On("Cookie", mock.MatchedBy(func(c *router.Cookie) bool {
		return c.Name == "jwt" && c.Value == "valid.jwt.token" && c.HTTPOnly
	})).Return()

	httpAuth, err := auth.NewHTTPAuthenticator(mockAuth, mockConfig)
	require.NoError(t, err)

	payload := MockLoginPayload{
		Identifier:      "user@example.com",
		Password:        "password123",
		ExtendedSession: true,
	}

	err = httpAuth.Login(mockCtx, payload)
	require.NoError(t, err)

	mockAuth.AssertExpectations(t)
	mockConfig.AssertExpectations(t)
	mockCtx.AssertExpectations(t)
}

func TestRouteAuthenticator_LoginError(t *testing.T) {
	mockAuth := new(MockAuthenticator)
	mockConfig := new(MockConfig)
	mockCtx := new(MockContext)

	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetExtendedTokenDuration").Return(48)

	authErr := errors.New("invalid credentials")
	mockAuth.On("Login", mock.Anything, "user@example.com", "wrongpass").Return("", authErr)

	mockCtx.On("Context").Return(context.Background())

	httpAuth, err := auth.NewHTTPAuthenticator(mockAuth, mockConfig)
	require.NoError(t, err)

	payload := MockLoginPayload{
		Identifier:      "user@example.com",
		Password:        "wrongpass",
		ExtendedSession: false,
	}

	err = httpAuth.Login(mockCtx, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "err authenticating payload")

	mockAuth.AssertExpectations(t)
	mockConfig.AssertExpectations(t)
	mockCtx.AssertExpectations(t)
}

func TestRouteAuthenticator_Logout(t *testing.T) {
	mockAuth := new(MockAuthenticator)
	mockConfig := new(MockConfig)
	mockCtx := new(MockContext)

	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetExtendedTokenDuration").Return(48)
	mockConfig.On("GetContextKey").Return("jwt")

	mockCtx.On("Cookie", mock.MatchedBy(func(c *router.Cookie) bool {
		return c.Name == "jwt" && c.Value == "" && c.HTTPOnly && c.Expires.Before(time.Now())
	})).Return()

	httpAuth, err := auth.NewHTTPAuthenticator(mockAuth, mockConfig)
	require.NoError(t, err)

	httpAuth.Logout(mockCtx)

	mockConfig.AssertExpectations(t)
	mockCtx.AssertExpectations(t)
}

func TestRouteAuthenticator_ProtectedRoute(t *testing.T) {
	mockAuth := new(MockAuthenticator)
	mockConfig := new(MockConfig)

	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetExtendedTokenDuration").Return(48)

	httpAuth, err := auth.NewHTTPAuthenticator(mockAuth, mockConfig)
	require.NoError(t, err)

	errorHandler := func(ctx router.Context, err error) error {
		return ctx.Status(http.StatusUnauthorized).SendString("Unauthorized")
	}

	middleware := httpAuth.ProtectedRoute(mockConfig, errorHandler)

	middlewareFunc := router.ToMiddleware(func(c router.Context) error { return nil })
	assert.IsType(t, middlewareFunc, middleware)

	mockConfig.AssertExpectations(t)
}

func TestRouteAuthenticator_RedirectFunctions(t *testing.T) {
	mockAuth := new(MockAuthenticator)
	mockConfig := new(MockConfig)

	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetExtendedTokenDuration").Return(48)
	mockConfig.On("GetRejectedRouteKey").Return("rejected_route").Times(3)
	mockConfig.On("GetRejectedRouteDefault").Return("/login")

	httpAuth, err := auth.NewHTTPAuthenticator(mockAuth, mockConfig)
	require.NoError(t, err)

	t.Run("SetRedirect", func(t *testing.T) {
		mockCtx := new(MockContext)

		mockCtx.On("OriginalURL").Return("/dashboard")
		mockCtx.On("Cookie", mock.MatchedBy(func(c *router.Cookie) bool {
			return c.Name == "rejected_route" && c.Value == "/dashboard" && c.HTTPOnly
		})).Return()

		httpAuth.SetRedirect(mockCtx)

		mockCtx.AssertExpectations(t)
	})

	t.Run("GetRedirect", func(t *testing.T) {
		mockCtx := new(MockContext)

		mockCtx.On("Cookies", "rejected_route").Return("/dashboard")
		mockCtx.On("Cookie", mock.MatchedBy(func(c *router.Cookie) bool {
			return c.Name == "rejected_route" && c.Value == "" && c.HTTPOnly && c.Expires.Before(time.Now())
		})).Return()

		redirect := httpAuth.GetRedirect(mockCtx, "/home")
		assert.Equal(t, "/dashboard", redirect)

		mockCtx.AssertExpectations(t)
	})

	t.Run("GetRedirectOrDefault", func(t *testing.T) {
		mockCtx := new(MockContext)

		mockCtx.On("Referer").Return("/some-referer")
		mockCtx.On("Cookies", "rejected_route", "/some-referer").Return("")
		mockCtx.On("Cookie", mock.MatchedBy(func(c *router.Cookie) bool {
			return c.Name == "rejected_route" && c.Value == "" && c.HTTPOnly && c.Expires.Before(time.Now())
		})).Return()

		redirect := httpAuth.GetRedirectOrDefault(mockCtx)
		assert.Equal(t, "/login", redirect)

		mockCtx.AssertExpectations(t)
	})

	mockConfig.AssertExpectations(t)
}

func TestRouteAuthenticator_Impersonate(t *testing.T) {
	mockAuth := new(MockAuthenticator)
	mockConfig := new(MockConfig)
	mockCtx := new(MockContext)

	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetExtendedTokenDuration").Return(48)
	mockConfig.On("GetContextKey").Return("jwt")

	mockAuth.On("Impersonate", mock.Anything, "admin@example.com").Return("admin.jwt.token", nil)

	mockCtx.On("Context").Return(context.Background())
	mockCtx.On("Cookie", mock.MatchedBy(func(c *router.Cookie) bool {
		return c.Name == "jwt" && c.Value == "admin.jwt.token" && c.HTTPOnly
	})).Return()

	httpAuth, err := auth.NewHTTPAuthenticator(mockAuth, mockConfig)
	require.NoError(t, err)

	err = httpAuth.Impersonate(mockCtx, "admin@example.com")
	require.NoError(t, err)

	mockAuth.AssertExpectations(t)
	mockConfig.AssertExpectations(t)
	mockCtx.AssertExpectations(t)
}

func TestRouteAuthenticator_MakeClientRouteAuthErrorHandler(t *testing.T) {
	mockAuth := new(MockAuthenticator)
	mockConfig := new(MockConfig)

	mockConfig.On("GetTokenExpiration").Return(24)
	mockConfig.On("GetExtendedTokenDuration").Return(48)

	httpAuth, err := auth.NewHTTPAuthenticator(mockAuth, mockConfig)
	require.NoError(t, err)

	t.Run("Optional Auth - Malformed Token", func(t *testing.T) {
		mockCtx := new(MockContext)

		handler := httpAuth.MakeClientRouteAuthErrorHandler(true)

		err := handler(mockCtx, jwtware.ErrJWTMissingOrMalformed)
		require.NoError(t, err)
		assert.True(t, mockCtx.NextCalled, "Next handler should be called for optional routes")

		mockCtx.AssertExpectations(t)
	})

	t.Run("Required Auth - Malformed Token", func(t *testing.T) {
		mockCtx := new(MockContext)

		var authErrorCalled bool
		origHandler := httpAuth.AuthErrorHandler
		httpAuth.AuthErrorHandler = func(c router.Context) error {
			authErrorCalled = true
			return c.Redirect("/login", http.StatusSeeOther)
		}
		defer func() { httpAuth.AuthErrorHandler = origHandler }()

		handler := httpAuth.MakeClientRouteAuthErrorHandler(false)

		mockCtx.On("Redirect", "/login", []int{http.StatusSeeOther}).Return(nil)

		err := handler(mockCtx, jwtware.ErrJWTMissingOrMalformed)
		require.NoError(t, err)
		assert.True(t, authErrorCalled, "Auth error handler should be called for required routes")

		mockCtx.AssertExpectations(t)
	})

	mockConfig.AssertExpectations(t)
}
