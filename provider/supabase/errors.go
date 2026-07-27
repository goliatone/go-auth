package supabase

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	auth "github.com/goliatone/go-auth"
)

var (
	ErrProviderUnavailable = errors.New("supabase: provider unavailable")
	ErrRateLimited         = errors.New("supabase: rate limited")
	ErrResponseTooLarge    = errors.New("supabase: response exceeds configured limit")
	ErrAmbiguousMutation   = errors.New("supabase: mutation result is ambiguous")
)

type ErrorKind string

const (
	ErrorInvalid      ErrorKind = "invalid"
	ErrorUnauthorized ErrorKind = "unauthorized"
	ErrorConflict     ErrorKind = "conflict"
	ErrorRateLimit    ErrorKind = "rate_limit"
	ErrorUnsupported  ErrorKind = "unsupported"
	ErrorExternal     ErrorKind = "external"
	ErrorAmbiguous    ErrorKind = "ambiguous"
)

type ProviderError struct {
	Kind       ErrorKind
	Code       string
	StatusCode int
	RequestID  string
	Retryable  bool
	Ambiguous  bool
	cause      error
}

func (e *ProviderError) Error() string {
	if e == nil {
		return "supabase: provider error"
	}
	return fmt.Sprintf("supabase: provider request failed (kind=%s status=%d request_id=%q)",
		e.Kind, e.StatusCode, strings.TrimSpace(e.RequestID))
}

func (e *ProviderError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

var safeProviderCode = regexp.MustCompile(`\A[A-Za-z0-9_.-]{1,128}\z`)

func safeErrorCode(value string) string {
	value = strings.TrimSpace(value)
	if !safeProviderCode.MatchString(value) {
		return ""
	}
	return value
}

func providerError(status int, code, requestID string) *ProviderError {
	out := &ProviderError{
		StatusCode: status,
		Code:       safeErrorCode(code),
		RequestID:  strings.TrimSpace(requestID),
	}
	switch status {
	case 400, 404, 405, 422:
		out.Kind, out.cause = ErrorInvalid, auth.ErrProviderOperationInvalid
	case 401, 403:
		out.Kind, out.cause = ErrorUnauthorized, auth.ErrProviderOperationUnauthorized
	case 409:
		out.Kind, out.cause = ErrorConflict, auth.ErrProviderOperationConflict
	case 429:
		out.Kind, out.cause, out.Retryable = ErrorRateLimit, ErrRateLimited, true
	case 501:
		out.Kind, out.cause = ErrorUnsupported, auth.ErrProviderOperationUnsupported
	default:
		out.Kind, out.cause = ErrorExternal, ErrProviderUnavailable
		out.Retryable = status == 502 || status == 503 || status == 504
	}
	return out
}

func ambiguousProviderError(requestID string, cause error) *ProviderError {
	return &ProviderError{
		Kind:      ErrorAmbiguous,
		RequestID: strings.TrimSpace(requestID),
		Ambiguous: true,
		cause:     errors.Join(ErrAmbiguousMutation, cause),
	}
}
