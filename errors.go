package auth

import (
	"strings"

	"github.com/goliatone/go-errors"
)

const (
	TextCodeInvalidCreds          = "INVALID_CREDENTIALS"
	TextCodeTooManyAttempts       = "TOO_MANY_ATTEMPTS"
	TextCodeSessionNotFound       = "SESSION_NOT_FOUND"
	TextCodeSessionDecodeError    = "SESSION_DECODE_ERROR"
	TextCodeClaimsMappingError    = "CLAIMS_MAPPING_ERROR"
	TextCodeDataParseError        = "DATA_PARSE_ERROR"
	TextCodeEmptyPassword         = "EMPTY_PASSWORD_NOT_ALLOWED"
	TextCodeTokenExpired          = "TOKEN_EXPIRED"
	TextCodeTokenMalformed        = "TOKEN_MALFORMED"
	TextCodeImmutableClaim        = "IMMUTABLE_CLAIM_MUTATION"
	TextCodeAccountSuspended      = "ACCOUNT_SUSPENDED"
	TextCodeAccountDisabled       = "ACCOUNT_DISABLED"
	TextCodeAccountArchived       = "ACCOUNT_ARCHIVED"
	TextCodeAccountPending        = "ACCOUNT_PENDING"
	TextCodeSignupDisabled        = "SIGNUP_DISABLED"
	TextCodePasswordResetDisabled = "PASSWORD_RESET_DISABLED"
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

// ErrImmutableClaimMutation is returned when a decorator tampers with protected claims.
var ErrImmutableClaimMutation = errors.New("claims decorator attempted to mutate immutable claim", errors.CategoryValidation).
	WithTextCode(TextCodeImmutableClaim).
	WithCode(errors.CodeBadRequest)

// ErrUserSuspended is returned when an account is suspended.
var ErrUserSuspended = errors.New("user account is suspended", errors.CategoryAuth).
	WithTextCode(TextCodeAccountSuspended).
	WithCode(errors.CodeForbidden)

// ErrUserDisabled is returned when an account is disabled.
var ErrUserDisabled = errors.New("user account is disabled", errors.CategoryAuth).
	WithTextCode(TextCodeAccountDisabled).
	WithCode(errors.CodeForbidden)

// ErrUserArchived is returned when an account is archived.
var ErrUserArchived = errors.New("user account is archived", errors.CategoryAuth).
	WithTextCode(TextCodeAccountArchived).
	WithCode(errors.CodeForbidden)

// ErrUserPending is returned when an account is pending activation.
var ErrUserPending = errors.New("user account is pending activation", errors.CategoryAuth).
	WithTextCode(TextCodeAccountPending).
	WithCode(errors.CodeForbidden)

// ErrSignupDisabled is returned when registrations are turned off by feature gates.
var ErrSignupDisabled = errors.New("signups are currently disabled", errors.CategoryAuthz).
	WithTextCode(TextCodeSignupDisabled).
	WithCode(errors.CodeForbidden)

// ErrPasswordResetDisabled is returned when password reset flows are disabled.
var ErrPasswordResetDisabled = errors.New("password reset is currently disabled", errors.CategoryAuthz).
	WithTextCode(TextCodePasswordResetDisabled).
	WithCode(errors.CodeForbidden)

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

func statusAuthError(status UserStatus) error {
	switch status {
	case UserStatusSuspended:
		return ErrUserSuspended
	case UserStatusDisabled:
		return ErrUserDisabled
	case UserStatusArchived:
		return ErrUserArchived
	case UserStatusPending:
		return ErrUserPending
	default:
		return nil
	}
}
