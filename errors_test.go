package auth_test

import (
	"errors"
	"testing"

	"github.com/goliatone/go-auth"
	"github.com/stretchr/testify/assert"
)

func TestIsTokenExpiredError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "Token expired error",
			err:      errors.New("token is expired"),
			expected: true,
		},
		{
			name:     "Token expired with prefix",
			err:      errors.New("error: token is expired"),
			expected: true,
		},
		{
			name:     "Token expired with suffix",
			err:      errors.New("token is expired by 5 minutes"),
			expected: true,
		},
		{
			name:     "Different error",
			err:      errors.New("invalid token"),
			expected: false,
		},
		{
			name:     "Nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.IsTokenExpiredError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsMalformedError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "Token malformed error",
			err:      errors.New("token is malformed"),
			expected: true,
		},
		{
			name:     "Missing or malformed JWT error",
			err:      errors.New("missing or malformed JWT"),
			expected: true,
		},
		{
			name:     "Token malformed with prefix",
			err:      errors.New("error: token is malformed"),
			expected: true,
		},
		{
			name:     "Missing JWT with suffix",
			err:      errors.New("missing or malformed JWT in request"),
			expected: true,
		},
		{
			name:     "Different error",
			err:      errors.New("invalid token"),
			expected: false,
		},
		{
			name:     "Nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.IsMalformedError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestErrorConstants(t *testing.T) {
	assert.Equal(t, "identity not found", auth.ErrIdentityNotFound.Error())
	assert.Equal(t, "unable to find session", auth.ErrUnableToFindSession.Error())
	assert.Equal(t, "unable to decode session", auth.ErrUnableToDecodeSession.Error())
	assert.Equal(t, "unable to map claims", auth.ErrUnableToMapClaims.Error())
	assert.Equal(t, "unable to parse data", auth.ErrUnableToParseData.Error())

	assert.Equal(t, "error too many login attempts", auth.ErrTooManyLoginAttempts.Error())

	assert.Equal(t, "auth: hashedPassword is not the hash of the given password", auth.ErrMismatchedHashAndPassword.Error())
}
