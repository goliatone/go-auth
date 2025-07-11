package auth

import (
	"errors"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword will generate a password hash
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", ErrNoEmptyString
	}

	h, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(h), err
}

// ComparePasswordAndHash will validate the given cleartext
// password matches the hashed password
func ComparePasswordAndHash(password, hash string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrMismatchedHashAndPassword
		}
		return err
	}
	return nil
}

// RandomPasswordHash is a temporary password
func RandomPasswordHash() string {
	pwd := uuid.New()

	h, err := HashPassword(pwd.String())
	if err != nil {
		return RandomPasswordHash()
	}

	return h
}
