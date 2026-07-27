package auth

import "reflect"

// StatusAwareIdentity is implemented by identities that expose an account
// lifecycle status. Identity implementations that predate lifecycle support
// remain compatible and are treated as active.
type StatusAwareIdentity interface {
	Status() UserStatus
}

// EnsureIdentityActive applies the provider-neutral account lifecycle gate used
// by every authentication flow before issuing or handing off a session.
func EnsureIdentityActive(identity Identity) (UserStatus, error) {
	if identity == nil || isNilIdentity(identity) {
		return "", ErrIdentityNotFound
	}

	statusAware, ok := identity.(StatusAwareIdentity)
	if !ok {
		return "", nil
	}

	status := statusAware.Status()
	if status == "" {
		status = UserStatusActive
	}
	if err := statusAuthError(status); err != nil {
		return status, err
	}
	return status, nil
}

func isNilIdentity(identity Identity) bool {
	value := reflect.ValueOf(identity)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
