package csrf

import (
	"testing"

	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestTokenHandlerSuccess(t *testing.T) {
	handler := tokenHandler(routeConfigDefault())

	ctx := router.NewMockContext()
	ctx.LocalsMock[DefaultContextKey] = "token123"
	ctx.LocalsMock[DefaultContextKey+"_field"] = "csrf_field"
	ctx.LocalsMock[DefaultContextKey+"_header"] = "X-CSRF-Token"
	ctx.On("SetHeader", "Cache-Control", "no-store, max-age=0").Return(ctx)
	ctx.On("SetHeader", "Pragma", "no-cache").Return(ctx)
	ctx.On("SetHeader", "Expires", "0").Return(ctx)

	var payload map[string]string
	ctx.On("JSON", router.StatusOK, mock.Anything).Run(func(args mock.Arguments) {
		payload = args.Get(1).(map[string]string)
	}).Return(nil).Once()

	require.NoError(t, handler(ctx))
	require.Equal(t, "token123", payload["token"])
	require.Equal(t, "csrf_field", payload["field_name"])
	require.Equal(t, "X-CSRF-Token", payload["header_name"])
}

func TestTokenHandlerMissingToken(t *testing.T) {
	handler := tokenHandler(routeConfigDefault())

	ctx := router.NewMockContext()
	ctx.On("SetHeader", mock.Anything, mock.Anything).Maybe().Return(ctx)

	ctx.On("JSON", router.StatusUnauthorized, mock.Anything).Return(nil).Once()

	require.NoError(t, handler(ctx))
}

func TestRouteConfigOverride(t *testing.T) {
	custom := RouteConfig{
		Path:       "/custom-csrf",
		ContextKey: "custom_token",
		RouteName:  "custom.csrf",
	}

	conf := routeConfigDefault(custom)
	require.Equal(t, "/custom-csrf", conf.Path)
	require.Equal(t, "custom_token", conf.ContextKey)
	require.Equal(t, "custom.csrf", conf.RouteName)
}
