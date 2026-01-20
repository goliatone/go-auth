package auth

// TokenValidator validates tokens and extracts claims without tying callers
// to a specific signing implementation.
type TokenValidator interface {
	Validate(tokenString string) (AuthClaims, error)
}

// TokenValidatorFunc adapts a function into a TokenValidator.
type TokenValidatorFunc func(tokenString string) (AuthClaims, error)

// Validate satisfies the TokenValidator interface.
func (f TokenValidatorFunc) Validate(tokenString string) (AuthClaims, error) {
	if f == nil {
		return nil, ErrUnableToDecodeSession
	}
	return f(tokenString)
}
