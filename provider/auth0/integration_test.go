//go:build integration
// +build integration

package auth0_test

import (
	"os"
	"testing"

	"github.com/goliatone/go-auth/provider/auth0"
	"github.com/stretchr/testify/require"
)

func TestAuth0Integration(t *testing.T) {
	domain := os.Getenv("AUTH0_DOMAIN")
	audience := os.Getenv("AUTH0_AUDIENCE")
	token := os.Getenv("AUTH0_TEST_TOKEN")
	if domain == "" || audience == "" || token == "" {
		t.Skip("AUTH0_DOMAIN, AUTH0_AUDIENCE, and AUTH0_TEST_TOKEN must be set")
	}

	validator, err := auth0.NewTokenValidator(auth0.Config{
		Domain:   domain,
		Audience: []string{audience},
	})
	require.NoError(t, err)

	claims, err := validator.Validate(token)
	require.NoError(t, err)
	require.NotEmpty(t, claims.UserID())
}
