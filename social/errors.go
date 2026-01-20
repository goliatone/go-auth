package social

import "github.com/goliatone/go-errors"

const (
	TextCodeProviderNotFound  = "social_provider_not_found"
	TextCodeInvalidState      = "social_invalid_state"
	TextCodeStateExpired      = "social_state_expired"
	TextCodeTokenExchangeFail = "social_token_exchange_failed"
	TextCodeUserInfoFail      = "social_user_info_failed"
	TextCodeEmailNotVerified  = "social_email_not_verified"
	TextCodeEmailExists       = "social_email_exists"
	TextCodeSignupDisabled    = "social_signup_disabled"
	TextCodeLinkingDisabled   = "social_linking_disabled"
	TextCodeLastAuthMethod    = "social_last_auth_method"
)

// ErrProviderNotFound is returned when a requested provider is not configured.
var ErrProviderNotFound = errors.New("social provider not found", errors.CategoryNotFound).
	WithTextCode(TextCodeProviderNotFound).
	WithCode(errors.CodeNotFound)

// ErrInvalidState is returned when the OAuth state is invalid or tampered.
var ErrInvalidState = errors.New("invalid oauth state", errors.CategoryBadInput).
	WithTextCode(TextCodeInvalidState).
	WithCode(errors.CodeBadRequest)

// ErrStateExpired is returned when the OAuth state has expired.
var ErrStateExpired = errors.New("oauth state expired", errors.CategoryBadInput).
	WithTextCode(TextCodeStateExpired).
	WithCode(errors.CodeBadRequest)

// ErrTokenExchangeFailed is returned when a provider token exchange fails.
var ErrTokenExchangeFailed = errors.New("token exchange failed", errors.CategoryAuth).
	WithTextCode(TextCodeTokenExchangeFail).
	WithCode(errors.CodeUnauthorized)

// ErrUserInfoFailed is returned when fetching user info fails.
var ErrUserInfoFailed = errors.New("failed to fetch user info", errors.CategoryAuth).
	WithTextCode(TextCodeUserInfoFail).
	WithCode(errors.CodeUnauthorized)

// ErrEmailNotVerified is returned when a provider email is not verified.
var ErrEmailNotVerified = errors.New("email not verified", errors.CategoryAuth).
	WithTextCode(TextCodeEmailNotVerified).
	WithCode(errors.CodeForbidden)

// ErrEmailAlreadyExists is returned when a user with the email already exists.
var ErrEmailAlreadyExists = errors.New("email already exists", errors.CategoryValidation).
	WithTextCode(TextCodeEmailExists).
	WithCode(errors.CodeConflict)

// ErrSignupNotAllowed is returned when signup is disabled.
var ErrSignupNotAllowed = errors.New("signup not allowed", errors.CategoryAuth).
	WithTextCode(TextCodeSignupDisabled).
	WithCode(errors.CodeForbidden)

// ErrLinkingNotAllowed is returned when account linking is disabled.
var ErrLinkingNotAllowed = errors.New("linking not allowed", errors.CategoryAuth).
	WithTextCode(TextCodeLinkingDisabled).
	WithCode(errors.CodeForbidden)

// ErrLastAuthMethod is returned when unlinking would remove the last auth method.
var ErrLastAuthMethod = errors.New("cannot unlink last authentication method", errors.CategoryValidation).
	WithTextCode(TextCodeLastAuthMethod).
	WithCode(errors.CodeBadRequest)
