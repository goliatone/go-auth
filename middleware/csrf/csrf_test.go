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

	mw := New(cfg)

	getCtx := newMockContextWithBase("GET")
	err := mw(getCtx)
	require.NoError(t, err)

	tokenVal, ok := getCtx.LocalsMock[DefaultContextKey].(string)
	require.True(t, ok)
	require.NotEmpty(t, tokenVal)

	postCtx := newMockContextWithBase("POST")
	postCtx.On("FormValue", DefaultFormFieldName).Return(tokenVal)

	err = mw(postCtx)
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

	mw := New(cfg)

	getCtx := newMockContextWithBase("GET")
	require.NoError(t, mw(getCtx))

	postCtx := newMockContextWithBase("POST")
	postCtx.On("FormValue", DefaultFormFieldName).Return("tampered")

	err := mw(postCtx)
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

	mw := New(cfg)

	getCtx := newMockContextWithBase("GET")
	require.NoError(t, mw(getCtx))

	tokenVal := getCtx.LocalsMock[DefaultContextKey].(string)

	time.Sleep(time.Millisecond) // ensure token is expired

	postCtx := newMockContextWithBase("POST")
	postCtx.On("FormValue", DefaultFormFieldName).Return(tokenVal)

	err := mw(postCtx)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrTokenExpired)
}
