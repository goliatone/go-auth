package oidc

import (
	"errors"

	goerrors "github.com/goliatone/go-errors"
)

func errorHasTextCode(err error, textCode string) bool {
	var richErr *goerrors.Error
	return errors.As(err, &richErr) && richErr.TextCode == textCode
}
