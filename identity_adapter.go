package auth

import "maps"

// UserIdentity adapts a User into the Identity interface for token generation.
type UserIdentity struct {
	user *User
}

// NewIdentityFromUser returns an Identity adapter for the provided user.
func NewIdentityFromUser(user *User) Identity {
	if user == nil {
		return nil
	}
	return UserIdentity{user: user}
}

// ID returns the user's ID as a string.
func (u UserIdentity) ID() string {
	if u.user == nil {
		return ""
	}
	return u.user.ID.String()
}

// Username returns the user's username.
func (u UserIdentity) Username() string {
	if u.user == nil {
		return ""
	}
	return u.user.Username
}

// Email returns the user's email address.
func (u UserIdentity) Email() string {
	if u.user == nil {
		return ""
	}
	return u.user.Email
}

// Role returns the user's role as a string.
func (u UserIdentity) Role() string {
	if u.user == nil {
		return ""
	}
	return string(u.user.Role)
}

// Status returns the user's lifecycle status.
func (u UserIdentity) Status() UserStatus {
	if u.user == nil {
		return ""
	}
	return u.user.Status
}

// Metadata returns a copy of user metadata that is safe for auth decorators.
func (u UserIdentity) Metadata() map[string]any {
	if u.user == nil || len(u.user.Metadata) == 0 {
		return nil
	}
	out := make(map[string]any, len(u.user.Metadata))
	maps.Copy(out, u.user.Metadata)
	return out
}
