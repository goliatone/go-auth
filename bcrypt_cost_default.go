//go:build !race

package auth

func passwordHashCost() int {
	return 14
}
