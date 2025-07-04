package auth_test

import (
	"errors"
	"testing"

	"github.com/goliatone/go-auth"
	goerrors "github.com/goliatone/go-errors"
	"github.com/stretchr/testify/assert"
)

func TestIsTokenExpiredError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		// {
		// 	name:     "Structured token expired error",
		// 	err:      auth.ErrTokenExpired,
		// 	expected: true,
		// },
		{
			name:     "Legacy token expired error (string match)",
			err:      errors.New("some wrapper: token is expired"),
			expected: true,
		},
		{
			name:     "Different structured error",
			err:      auth.ErrIdentityNotFound,
			expected: false,
		},
		{
			name:     "Different legacy error",
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
		// {
		// 	name:     "Structured malformed error",
		// 	err:      auth.ErrTokenMalformed,
		// 	expected: true,
		// },
		{
			name:     "Legacy malformed error (string match)",
			err:      errors.New("token is malformed"),
			expected: true,
		},
		{
			name:     "Legacy missing JWT error (string match)",
			err:      errors.New("missing or malformed JWT"),
			expected: true,
		},
		// {
		// 	name:     "Different structured error",
		// 	err:      auth.ErrTokenExpired,
		// 	expected: false,
		// },
		{
			name:     "Different legacy error",
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

func TestStructuredErrorProperties(t *testing.T) {
	t.Run("ErrIdentityNotFound", func(t *testing.T) {
		assert.Equal(t, goerrors.CategoryNotFound, auth.ErrIdentityNotFound.Category)
		assert.Equal(t, "identity not found", auth.ErrIdentityNotFound.Message)
	})

	t.Run("ErrMismatchedHashAndPassword", func(t *testing.T) {
		assert.Equal(t, goerrors.CategoryAuth, auth.ErrMismatchedHashAndPassword.Category)
		assert.Equal(t, auth.TextCodeInvalidCreds, auth.ErrMismatchedHashAndPassword.TextCode)
		assert.Equal(t, "the credentials provided are invalid", auth.ErrMismatchedHashAndPassword.Message)
	})

	t.Run("ErrTooManyLoginAttempts", func(t *testing.T) {
		assert.Equal(t, goerrors.CategoryRateLimit, auth.ErrTooManyLoginAttempts.Category)
		assert.Equal(t, auth.TextCodeTooManyAttempts, auth.ErrTooManyLoginAttempts.TextCode)
	})

	t.Run("ErrUnableToFindSession", func(t *testing.T) {
		assert.Equal(t, goerrors.CategoryAuth, auth.ErrUnableToFindSession.Category)
		assert.Equal(t, auth.TextCodeSessionNotFound, auth.ErrUnableToFindSession.TextCode)
	})

	t.Run("ErrUnableToDecodeSession", func(t *testing.T) {
		assert.Equal(t, goerrors.CategoryAuth, auth.ErrUnableToDecodeSession.Category)
		assert.Equal(t, auth.TextCodeSessionDecodeError, auth.ErrUnableToDecodeSession.TextCode)
	})

	t.Run("ErrUnableToMapClaims", func(t *testing.T) {
		assert.Equal(t, goerrors.CategoryAuth, auth.ErrUnableToMapClaims.Category)
		assert.Equal(t, auth.TextCodeClaimsMappingError, auth.ErrUnableToMapClaims.TextCode)
	})

	t.Run("ErrUnableToParseData", func(t *testing.T) {
		assert.Equal(t, goerrors.CategoryBadInput, auth.ErrUnableToParseData.Category)
		assert.Equal(t, auth.TextCodeDataParseError, auth.ErrUnableToParseData.TextCode)
	})

	t.Run("ErrNoEmptyString", func(t *testing.T) {
		assert.Equal(t, goerrors.CategoryValidation, auth.ErrNoEmptyString.Category)
		assert.Equal(t, auth.TextCodeEmptyPassword, auth.ErrNoEmptyString.TextCode)
	})

	// t.Run("ErrTokenExpired", func(t *testing.T) {
	// 	assert.Equal(t, goerrors.CategoryAuth, auth.ErrTokenExpired.Category)
	// 	assert.Equal(t, auth.TextCodeTokenExpired, auth.ErrTokenExpired.TextCode)
	// })
}
