package auth

import "context"

var userCtxKey = &contextKey{"user"}

type contextKey struct {
	name string
}

// WithContext sets the User in the given context
func WithContext(r context.Context, user *User) context.Context {
	return context.WithValue(r, userCtxKey, user)
}

// FromContext finds the user from the context.
func FromContext(ctx context.Context) *User {
	raw, _ := ctx.Value(userCtxKey).(*User)
	return raw
}
