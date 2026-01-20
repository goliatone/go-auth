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

// MultiTokenValidator tries validators in order until one succeeds.
// It treats ErrTokenMalformed as "try next" and returns the last malformed
// error if all validators fail.
type MultiTokenValidator struct {
	validators []TokenValidator
}

// NewMultiTokenValidator filters nil validators and returns a composite validator.
func NewMultiTokenValidator(validators ...TokenValidator) *MultiTokenValidator {
	filtered := make([]TokenValidator, 0, len(validators))
	for _, v := range validators {
		if v != nil {
			filtered = append(filtered, v)
		}
	}
	return &MultiTokenValidator{validators: filtered}
}

// Validate satisfies the TokenValidator interface.
func (m *MultiTokenValidator) Validate(tokenString string) (AuthClaims, error) {
	var lastErr error
	for _, v := range m.validators {
		claims, err := v.Validate(tokenString)
		if err == nil {
			return claims, nil
		}
		if IsMalformedError(err) {
			lastErr = err
			continue
		}
		return nil, err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrTokenMalformed
}
