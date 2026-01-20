package auth

// HasUserUUID reports whether Session.GetUserUUID will succeed.
func HasUserUUID(session Session) bool {
	if session == nil {
		return false
	}
	_, err := session.GetUserUUID()
	return err == nil
}
