package auth

import (
	"strings"

	"github.com/goliatone/go-errors"
)

const (
	TextCodeInvalidCreds       = "INVALID_CREDENTIALS"
	TextCodeTooManyAttempts    = "TOO_MANY_ATTEMPTS"
	TextCodeSessionNotFound    = "SESSION_NOT_FOUND"
	TextCodeSessionDecodeError = "SESSION_DECODE_ERROR"
	TextCodeClaimsMappingError = "CLAIMS_MAPPING_ERROR"
	TextCodeDataParseError     = "DATA_PARSE_ERROR"
	TextCodeEmptyPassword      = "EMPTY_PASSWORD_NOT_ALLOWED"
	TextCodeTokenExpired       = "TOKEN_EXPIRED"
	TextCodeTokenMalformed     = "TOKEN_MALFORMED"
)

// ErrIdentityNotFound is returned when an identity cannot be found.
var ErrIdentityNotFound = errors.New("identity not found", errors.CategoryNotFound).
	WithCode(errors.CodeNotFound)

// ErrMismatchedHashAndPassword is returned on a failure to check a password hash.
// The message is generic to avoid leaking information.
var ErrMismatchedHashAndPassword = errors.New("the credentials provided are invalid", errors.CategoryAuth).
	WithTextCode(TextCodeInvalidCreds).
	WithCode(errors.CodeUnauthorized)

// ErrTooManyLoginAttempts indicates the user has tried to log in too many times.
var ErrTooManyLoginAttempts = errors.New("too many login attempts, please try again later", errors.CategoryRateLimit).
	WithTextCode(TextCodeTooManyAttempts).
	WithCode(errors.CodeTooManyRequests)

// ErrUnableToFindSession is returned when a session (e.g., a cookie) is missing from a request.
var ErrUnableToFindSession = errors.New("unable to find session", errors.CategoryAuth).
	WithTextCode(TextCodeSessionNotFound).
	WithCode(errors.CodeUnauthorized)

// ErrUnableToDecodeSession is returned when a session token (e.g., JWT) cannot be decoded or parsed.
var ErrUnableToDecodeSession = errors.New("unable to decode session", errors.CategoryAuth).
	WithTextCode(TextCodeSessionDecodeError).
	WithCode(errors.CodeUnauthorized)

// ErrUnableToMapClaims is returned when claims cannot be extracted from a parsed token.
var ErrUnableToMapClaims = errors.New("unable to map claims from token", errors.CategoryAuth).
	WithTextCode(TextCodeClaimsMappingError).
	WithCode(errors.CodeUnauthorized)

// ErrUnableToParseData is returned on a generic data parsing error within the auth context.
var ErrUnableToParseData = errors.New("unable to parse authentication data", errors.CategoryBadInput).
	WithTextCode(TextCodeDataParseError).
	WithCode(errors.CodeBadRequest)

// ErrNoEmptyString is returned when an empty string is provided for a value that must not be empty, like a password.
var ErrNoEmptyString = errors.New("password can't be an empty string", errors.CategoryValidation).
	WithTextCode(TextCodeEmptyPassword).
	WithCode(errors.CodeBadRequest)

// ErrTokenExpired is returned when a JWT token has expired.
var ErrTokenExpired = errors.New("token is expired", errors.CategoryAuth).
	WithTextCode(TextCodeTokenExpired).
	WithCode(errors.CodeUnauthorized)

// ErrTokenMalformed is returned when a JWT token is malformed.
var ErrTokenMalformed = errors.New("token is malformed", errors.CategoryAuth).
	WithTextCode(TextCodeTokenMalformed).
	WithCode(errors.CodeBadRequest)

func IsTokenExpiredError(err error) bool {
	if err == nil {
		return false
	}

	var richErr *errors.Error
	if errors.As(err, &richErr) {
		return richErr.TextCode == TextCodeTokenExpired
	}

	return strings.Contains(err.Error(), "token is expired")
}

func IsMalformedError(err error) bool {
	if err == nil {
		return false
	}

	var richErr *errors.Error
	if errors.As(err, &richErr) {
		return richErr.TextCode == TextCodeTokenMalformed
	}

	return strings.Contains(err.Error(), "token is malformed") ||
		strings.Contains(err.Error(), "missing or malformed JWT")
}
