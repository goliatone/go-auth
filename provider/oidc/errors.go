package oidc

import (
	"strings"

	"github.com/goliatone/go-errors"
)

const (
	TextCodeOIDCInvalidConfig    = "OIDC_INVALID_CONFIG"
	TextCodeOIDCDiscoveryFailed  = "OIDC_DISCOVERY_FAILED"
	TextCodeOIDCInvalidState     = "OIDC_INVALID_STATE"
	TextCodeOIDCInvalidNonce     = "OIDC_INVALID_NONCE"
	TextCodeOIDCUnsafeRedirect   = "OIDC_UNSAFE_REDIRECT"
	TextCodeOIDCTokenExchange    = "OIDC_TOKEN_EXCHANGE_FAILED" // #nosec G101 -- Error text code, not a credential.
	TextCodeOIDCInvalidIDToken   = "OIDC_INVALID_ID_TOKEN"      // #nosec G101 -- Error text code, not a credential.
	TextCodeOIDCUserInfoFailed   = "OIDC_USERINFO_FAILED"
	TextCodeOIDCLinkingRejected  = "OIDC_LINKING_REJECTED"
	TextCodeOIDCDuplicateSubject = "OIDC_DUPLICATE_SUBJECT"
)

var (
	ErrInvalidConfig = errors.New("oidc configuration is invalid", errors.CategoryValidation).
				WithTextCode(TextCodeOIDCInvalidConfig).
				WithCode(errors.CodeBadRequest)
	ErrDiscoveryFailed = errors.New("oidc discovery failed", errors.CategoryExternal).
				WithTextCode(TextCodeOIDCDiscoveryFailed).
				WithCode(errors.CodeInternal)
	ErrInvalidState = errors.New("oidc state is invalid", errors.CategoryAuth).
			WithTextCode(TextCodeOIDCInvalidState).
			WithCode(errors.CodeUnauthorized)
	ErrInvalidNonce = errors.New("oidc nonce is invalid", errors.CategoryAuth).
			WithTextCode(TextCodeOIDCInvalidNonce).
			WithCode(errors.CodeUnauthorized)
	ErrUnsafeRedirect = errors.New("oidc redirect target is not allowed", errors.CategoryValidation).
				WithTextCode(TextCodeOIDCUnsafeRedirect).
				WithCode(errors.CodeBadRequest)
	ErrTokenExchangeFailed = errors.New("oidc token exchange failed", errors.CategoryExternal).
				WithTextCode(TextCodeOIDCTokenExchange).
				WithCode(errors.CodeInternal)
	ErrInvalidIDToken = errors.New("oidc id token is invalid", errors.CategoryAuth).
				WithTextCode(TextCodeOIDCInvalidIDToken).
				WithCode(errors.CodeUnauthorized)
	ErrUserInfoFailed = errors.New("oidc userinfo request failed", errors.CategoryExternal).
				WithTextCode(TextCodeOIDCUserInfoFailed).
				WithCode(errors.CodeInternal)
	ErrLinkingRejected = errors.New("oidc identity linking was rejected", errors.CategoryAuthz).
				WithTextCode(TextCodeOIDCLinkingRejected).
				WithCode(errors.CodeForbidden)
	ErrDuplicateSubject = errors.New("oidc subject maps to more than one user", errors.CategoryConflict).
				WithTextCode(TextCodeOIDCDuplicateSubject).
				WithCode(errors.CodeConflict)
)

func cloneWithProvider(err *errors.Error, providerKey string, metadata map[string]any) error {
	if err == nil {
		return nil
	}
	clone := err.Clone()
	if clone == nil {
		clone = err
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	if key := strings.TrimSpace(providerKey); key != "" {
		metadata["provider"] = key
	}
	return clone.WithMetadata(metadata)
}
