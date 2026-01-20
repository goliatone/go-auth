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
	mockCtx := router.NewMockContext()

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
	mockCtx := router.NewMockContext()

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
	assert.Contains(t, err.Error(), "invalid credentials")

	mockAuth.AssertExpectations(t)
	mockConfig.AssertExpectations(t)
	mockCtx.AssertExpectations(t)
}

func TestRouteAuthenticator_Logout(t *testing.T) {
	mockAuth := new(MockAuthenticator)
	mockConfig := new(MockConfig)
	mockCtx := router.NewMockContext()

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
	mockConfig.On("GetSigningKey").Return("secret")
	mockConfig.On("GetSigningMethod").Return("HS256")
	mockConfig.On("GetAuthScheme").Return("Bearer")
	mockConfig.On("GetContextKey").Return("user")
	mockConfig.On("GetTokenLookup").Return("header:Authorization")

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
	mockConfig.On("GetRejectedRouteKey").Return("rejected_route").Maybe()
	mockConfig.On("GetRejectedRouteDefault").Return("/login")

	httpAuth, err := auth.NewHTTPAuthenticator(mockAuth, mockConfig)
	require.NoError(t, err)

	t.Run("SetRedirect", func(t *testing.T) {
		mockCtx := router.NewMockContext()

		mockCtx.On("OriginalURL").Return("/dashboard")
		mockCtx.On("Cookie", mock.MatchedBy(func(c *router.Cookie) bool {
			return c.Name == "rejected_route" && c.Value == "/dashboard" && c.HTTPOnly
		})).Return()

		httpAuth.SetRedirect(mockCtx)

		mockCtx.AssertExpectations(t)
	})

	t.Run("GetRedirect_WithCookie", func(t *testing.T) {
		mockCtx := router.NewMockContext()

		// NOTE: we need to set the cookie value directly in the mock map
		// instead of trying to mock the Cookies method
		mockCtx.CookiesM["rejected_route"] = "/dashboard"

		mockCtx.On("Cookie", mock.MatchedBy(func(c *router.Cookie) bool {
			return c.Name == "rejected_route" && c.Value == "" && c.HTTPOnly && c.Expires.Before(time.Now())
		})).Return()

		redirect := httpAuth.GetRedirect(mockCtx, "/home")
		assert.Equal(t, "/dashboard", redirect)

		assert.Equal(t, "", mockCtx.CookiesM["rejected_route"])

		mockCtx.AssertExpectations(t)
	})

	t.Run("GetRedirect_WithoutCookie", func(t *testing.T) {
		mockCtx := router.NewMockContext()

		redirect := httpAuth.GetRedirect(mockCtx, "/home")
		assert.Equal(t, "/home", redirect)

		mockCtx.AssertExpectations(t)
	})

	t.Run("GetRedirectOrDefault_WithReferer", func(t *testing.T) {
		mockCtx := router.NewMockContext()

		mockCtx.CookiesM["rejected_route"] = "/some-referer"

		mockCtx.On("Referer").Return("/some-referer")

		mockCtx.On("Cookie", mock.MatchedBy(func(c *router.Cookie) bool {
			return c.Name == "rejected_route" && c.Value == "" && c.HTTPOnly && c.Expires.Before(time.Now())
		})).Return()

		redirect := httpAuth.GetRedirectOrDefault(mockCtx)
		assert.Equal(t, "/some-referer", redirect)

		assert.Equal(t, "", mockCtx.CookiesM["rejected_route"])

		mockCtx.AssertExpectations(t)
	})

	t.Run("GetRedirectOrDefault_UsesConfigDefault", func(t *testing.T) {
		mockCtx := router.NewMockContext()

		mockCtx.On("Referer").Return("")

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
	mockCtx := router.NewMockContext()

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
		mockCtx := router.NewMockContext()

		handler := httpAuth.MakeClientRouteAuthErrorHandler(true)

		err := handler(mockCtx, jwtware.ErrJWTMissingOrMalformed)
		require.NoError(t, err)
		assert.True(t, mockCtx.NextCalled, "Next handler should be called for optional routes")

		mockCtx.AssertExpectations(t)
	})

	t.Run("Required Auth - Malformed Token", func(t *testing.T) {
		mockCtx := router.NewMockContext()

		var authErrorCalled bool
		var authErr error
		origHandler := httpAuth.AuthErrorHandler
		httpAuth.AuthErrorHandler = func(c router.Context, err error) error {
			authErrorCalled = true
			authErr = err
			return c.Redirect("/login", http.StatusSeeOther)
		}
		defer func() { httpAuth.AuthErrorHandler = origHandler }()

		handler := httpAuth.MakeClientRouteAuthErrorHandler(false)

		mockCtx.On("Redirect", "/login", []int{http.StatusSeeOther}).Return(nil)

		err := handler(mockCtx, jwtware.ErrJWTMissingOrMalformed)
		require.NoError(t, err)
		assert.True(t, authErrorCalled, "Auth error handler should be called for required routes")
		assert.True(t, auth.IsMalformedError(authErr))

		mockCtx.AssertExpectations(t)
	})

	t.Run("Required Auth - Expired Token", func(t *testing.T) {
		mockCtx := router.NewMockContext()

		var authErr error
		origHandler := httpAuth.AuthErrorHandler
		httpAuth.AuthErrorHandler = func(c router.Context, err error) error {
			authErr = err
			return nil
		}
		defer func() { httpAuth.AuthErrorHandler = origHandler }()

		handler := httpAuth.MakeClientRouteAuthErrorHandler(false)

		err := handler(mockCtx, auth.ErrTokenExpired)
		require.NoError(t, err)
		assert.True(t, auth.IsTokenExpiredError(authErr))
	})

	t.Run("Required Auth - Token Malformed", func(t *testing.T) {
		mockCtx := router.NewMockContext()

		var authErr error
		origHandler := httpAuth.AuthErrorHandler
		httpAuth.AuthErrorHandler = func(c router.Context, err error) error {
			authErr = err
			return nil
		}
		defer func() { httpAuth.AuthErrorHandler = origHandler }()

		handler := httpAuth.MakeClientRouteAuthErrorHandler(false)

		err := handler(mockCtx, auth.ErrTokenMalformed)
		require.NoError(t, err)
		assert.True(t, auth.IsMalformedError(authErr))
	})

	mockConfig.AssertExpectations(t)
}
