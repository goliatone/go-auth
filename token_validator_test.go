package auth_test

import (
	"errors"
	"testing"

	"github.com/goliatone/go-auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type validatorStub struct {
	calls  int
	claims auth.AuthClaims
	err    error
}

func (v *validatorStub) Validate(tokenString string) (auth.AuthClaims, error) {
	v.calls++
	return v.claims, v.err
}

func TestMultiTokenValidator_UsesFirstSuccess(t *testing.T) {
	claims := &auth.JWTClaims{}
	primary := &validatorStub{claims: claims}
	secondary := &validatorStub{claims: &auth.JWTClaims{}}

	validator := auth.NewMultiTokenValidator(primary, secondary)

	result, err := validator.Validate("token")
	require.NoError(t, err)
	assert.Same(t, claims, result)
	assert.Equal(t, 1, primary.calls)
	assert.Equal(t, 0, secondary.calls)
}

func TestMultiTokenValidator_FallbacksOnMalformed(t *testing.T) {
	claims := &auth.JWTClaims{}
	primary := &validatorStub{err: errors.New("token is malformed")}
	secondary := &validatorStub{claims: claims}

	validator := auth.NewMultiTokenValidator(primary, secondary)

	result, err := validator.Validate("token")
	require.NoError(t, err)
	assert.Same(t, claims, result)
	assert.Equal(t, 1, primary.calls)
	assert.Equal(t, 1, secondary.calls)
}

func TestMultiTokenValidator_ReturnsNonMalformedError(t *testing.T) {
	primary := &validatorStub{err: auth.ErrTokenExpired}
	secondary := &validatorStub{claims: &auth.JWTClaims{}}

	validator := auth.NewMultiTokenValidator(primary, secondary)

	result, err := validator.Validate("token")
	assert.Nil(t, result)
	assert.True(t, auth.IsTokenExpiredError(err))
	assert.Equal(t, 1, primary.calls)
	assert.Equal(t, 0, secondary.calls)
}

func TestMultiTokenValidator_AllMalformed(t *testing.T) {
	primary := &validatorStub{err: errors.New("token is malformed")}
	secondary := &validatorStub{err: errors.New("missing or malformed JWT")}

	validator := auth.NewMultiTokenValidator(primary, secondary)

	result, err := validator.Validate("token")
	assert.Nil(t, result)
	assert.True(t, auth.IsMalformedError(err))
	assert.Equal(t, 1, primary.calls)
	assert.Equal(t, 1, secondary.calls)
}

func TestMultiTokenValidator_EmptyValidators(t *testing.T) {
	validator := auth.NewMultiTokenValidator(nil, nil)

	result, err := validator.Validate("token")
	assert.Nil(t, result)
	assert.True(t, auth.IsMalformedError(err))
}
