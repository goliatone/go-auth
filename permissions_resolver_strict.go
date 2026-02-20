package auth

// ValidateResolverConfigured enforces resolver presence when strict mode is enabled.
func ValidateResolverConfigured(strict bool, resolver PermissionResolverFunc) error {
	if !strict {
		return nil
	}
	if resolver != nil {
		return nil
	}
	return ErrPermissionResolverRequired
}

// MustValidateResolverConfigured is a panic wrapper around ValidateResolverConfigured.
func MustValidateResolverConfigured(strict bool, resolver PermissionResolverFunc) {
	if err := ValidateResolverConfigured(strict, resolver); err != nil {
		panic(err)
	}
}
