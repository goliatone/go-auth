package csrf

import (
	"testing"
	"time"

	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newTestSecureKey() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func newMockContextWithBase(method string) *router.MockContext {
	ctx := router.NewMockContext()
	ctx.On("Method").Return(method)
	ctx.On("IP").Return("127.0.0.1")
	ctx.On("Locals", DefaultContextKey, mock.Anything).Return(nil)
	ctx.On("Locals", DefaultContextKey+"_field", mock.Anything).Return(nil)
	ctx.On("Locals", DefaultContextKey+"_header", mock.Anything).Return(nil)
	return ctx
}

func TestStatelessTokenValidationSuccess(t *testing.T) {
	key := newTestSecureKey()
	cfg := Config{
		SecureKey: key,
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := New(cfg)(func(ctx router.Context) error { return nil })

	getCtx := newMockContextWithBase("GET")
	err := handler(getCtx)
	require.NoError(t, err)

	tokenVal, ok := getCtx.LocalsMock[DefaultContextKey].(string)
	require.True(t, ok)
	require.NotEmpty(t, tokenVal)

	postCtx := newMockContextWithBase("POST")
	postCtx.On("FormValue", DefaultFormFieldName).Return(tokenVal)

	err = handler(postCtx)
	require.NoError(t, err)
	require.True(t, postCtx.NextCalled)
}

func TestStatelessTokenValidationMismatch(t *testing.T) {
	key := newTestSecureKey()
	var captured error
	cfg := Config{
		SecureKey: key,
		ErrorHandler: func(ctx router.Context, err error) error {
			captured = err
			return err
		},
	}

	handler := New(cfg)(func(ctx router.Context) error { return nil })

	getCtx := newMockContextWithBase("GET")
	require.NoError(t, handler(getCtx))

	postCtx := newMockContextWithBase("POST")
	postCtx.On("FormValue", DefaultFormFieldName).Return("tampered")

	err := handler(postCtx)
	require.Error(t, err)
	require.ErrorIs(t, captured, ErrTokenMismatch)
}

func TestStatelessTokenExpiration(t *testing.T) {
	key := newTestSecureKey()
	cfg := Config{
		SecureKey:  key,
		Expiration: time.Nanosecond,
		ErrorHandler: func(ctx router.Context, err error) error {
			return err
		},
	}

	handler := New(cfg)(func(ctx router.Context) error { return nil })

	getCtx := newMockContextWithBase("GET")
	require.NoError(t, handler(getCtx))

	tokenVal := getCtx.LocalsMock[DefaultContextKey].(string)

	time.Sleep(time.Millisecond) // ensure token is expired

	postCtx := newMockContextWithBase("POST")
	postCtx.On("FormValue", DefaultFormFieldName).Return(tokenVal)

	err := handler(postCtx)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrTokenExpired)
}

func TestShortSecureKeyPanics(t *testing.T) {
	require.Panics(t, func() {
		handler := New(Config{SecureKey: []byte("short")})(func(ctx router.Context) error { return nil })
		handler(newMockContextWithBase("GET"))
	})
}
