package social

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateManager_EncryptDecrypt(t *testing.T) {
	sm := NewEncryptedStateManager(
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("fedcba9876543210fedcba9876543210"),
		10*time.Minute,
	)

	state := &OAuthState{
		Provider:     "github",
		Action:       "login",
		RedirectURL:  "/dashboard",
		CodeVerifier: "test-verifier",
	}

	encoded, err := sm.Encode(state)
	require.NoError(t, err)

	decoded, err := sm.Decode(encoded)
	require.NoError(t, err)

	assert.Equal(t, state.Provider, decoded.Provider)
	assert.Equal(t, state.Action, decoded.Action)
	assert.Equal(t, state.RedirectURL, decoded.RedirectURL)
	assert.Equal(t, state.CodeVerifier, decoded.CodeVerifier)
}

func TestStateManager_ExpiredState(t *testing.T) {
	sm := NewEncryptedStateManager(
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("fedcba9876543210fedcba9876543210"),
		-1*time.Minute,
	)

	state := &OAuthState{Provider: "github"}
	encoded, err := sm.Encode(state)
	require.NoError(t, err)

	_, err = sm.Decode(encoded)
	assert.ErrorIs(t, err, ErrStateExpired)
}
