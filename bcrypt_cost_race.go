//go:build race

package auth

import "golang.org/x/crypto/bcrypt"

func passwordHashCost() int {
	// Reduce cost for race-enabled builds so test suites can run with strict timeouts.
	return bcrypt.DefaultCost
}
