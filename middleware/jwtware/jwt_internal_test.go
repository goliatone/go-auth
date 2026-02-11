package jwtware

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKeyfuncOptionsRefreshErrorHandlerIsSafe(t *testing.T) {
	opts := keyfuncOptions(nil)
	require.NotNil(t, opts.RefreshErrorHandler)
	require.NotPanics(t, func() {
		opts.RefreshErrorHandler(errors.New("refresh failed"))
	})

	require.Equal(t, time.Hour, opts.RefreshInterval)
	require.Equal(t, 5*time.Minute, opts.RefreshRateLimit)
	require.Equal(t, 10*time.Second, opts.RefreshTimeout)
	require.True(t, opts.RefreshUnknownKID)
}
