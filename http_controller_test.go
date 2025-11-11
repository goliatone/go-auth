package auth

import (
	"testing"

	csfmw "github.com/goliatone/go-auth/middleware/csrf"
	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMergeTemplateDataInjectsCSRFHelpers(t *testing.T) {
	ctx := router.NewMockContext()
	token := "csrf-token-123"

	ctx.LocalsMock[csfmw.DefaultContextKey] = token
	ctx.LocalsMock[csfmw.DefaultContextKey+"_field"] = "_token"
	ctx.LocalsMock[csfmw.DefaultContextKey+"_header"] = "X-CSRF-Token"
	ctx.On("LocalsMerge", csfmw.DefaultTemplateHelpersKey, mock.Anything).Return(map[string]any{})

	viewCtx := MergeTemplateData(ctx, router.ViewContext{
		"title": "login",
	})

	require.Equal(t, "login", viewCtx["title"])

	helpers, ok := ctx.LocalsMock[csfmw.DefaultTemplateHelpersKey].(map[string]any)
	require.True(t, ok, "helpers should be stored in locals")
	require.Equal(t, token, helpers["csrf_token"])

	field, ok := helpers["csrf_field"].(string)
	require.True(t, ok, "csrf_field should be a string input")
	require.Contains(t, field, `value="`+token+`"`)
	require.Contains(t, field, `name="_token"`)
}

func TestLoginShowAddsCSRFHelpersToView(t *testing.T) {
	ctrl := newTestAuthController()
	ctx := router.NewMockContext()
	token := "req-token-login"

	ctx.LocalsMock[csfmw.DefaultContextKey] = token
	ctx.LocalsMock[csfmw.DefaultContextKey+"_field"] = "_token"
	ctx.LocalsMock[csfmw.DefaultContextKey+"_header"] = "X-CSRF-Token"
	ctx.On("LocalsMerge", csfmw.DefaultTemplateHelpersKey, mock.Anything).Return(map[string]any{})

	ctx.On("Render", ctrl.Views.Login, mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		_, ok := args.Get(1).(router.ViewContext)
		require.True(t, ok, "expected router.ViewContext")

		helpers, ok := ctx.LocalsMock[csfmw.DefaultTemplateHelpersKey].(map[string]any)
		require.True(t, ok)
		require.Equal(t, token, helpers["csrf_token"])
		field := helpers["csrf_field"].(string)
		require.Contains(t, field, token)
	})

	err := ctrl.LoginShow(ctx)
	require.NoError(t, err)
	ctx.AssertExpectations(t)
}

func TestRegistrationShowAddsCSRFHelpersToView(t *testing.T) {
	ctrl := newTestAuthController()
	ctx := router.NewMockContext()
	token := "req-token-register"

	ctx.LocalsMock[csfmw.DefaultContextKey] = token
	ctx.LocalsMock[csfmw.DefaultContextKey+"_field"] = "_token"
	ctx.LocalsMock[csfmw.DefaultContextKey+"_header"] = "X-CSRF-Token"
	ctx.On("LocalsMerge", csfmw.DefaultTemplateHelpersKey, mock.Anything).Return(map[string]any{})

	ctx.On("Render", ctrl.Views.Register, mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		_, ok := args.Get(1).(router.ViewContext)
		require.True(t, ok, "expected router.ViewContext")

		helpers, ok := ctx.LocalsMock[csfmw.DefaultTemplateHelpersKey].(map[string]any)
		require.True(t, ok)
		require.Equal(t, token, helpers["csrf_token"])
		field := helpers["csrf_field"].(string)
		require.Contains(t, field, token)
	})

	err := ctrl.RegistrationShow(ctx)
	require.NoError(t, err)
	ctx.AssertExpectations(t)
}

func newTestAuthController() *AuthController {
	return &AuthController{
		Logger:       defLogger{},
		ErrorHandler: defaultErrHandler,
		Routes:       &AuthControllerRoutes{},
		Views: &AuthControllerViews{
			Login:    "login",
			Register: "register",
		},
	}
}
