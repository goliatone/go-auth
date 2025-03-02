package auth

import (
	"errors"
	"strings"
)

// ErrIdentityNotFound is the error we return for non found identities
var ErrIdentityNotFound = errors.New("identity not found")

// ErrUnableToFindSession is the error when our reequest has no cookie
var ErrUnableToFindSession = errors.New("unable to find session")

// ErrUnableToDecodeSession unable to decode JWT from session cookie
var ErrUnableToDecodeSession = errors.New("unable to decode session")

// ErrUnableToMapClaims unable to get claims from token
var ErrUnableToMapClaims = errors.New("unable to map claims")

// ErrUnableToParseData parse error
var ErrUnableToParseData = errors.New("unable to parse data")

// IsTokenExpiredError will check for expired tokens
func IsTokenExpiredError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "token is expired")
}

// IsMalformedError will check for error message
func IsMalformedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "token is malformed") ||
		strings.Contains(err.Error(), "missing or malformed JWT")
}
