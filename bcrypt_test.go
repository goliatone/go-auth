package auth_test

import (
	"testing"

	"github.com/goliatone/go-auth"
	"github.com/stretchr/testify/assert"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "Valid password",
			password: "securePassword123!",
			wantErr:  false,
		},
		{
			name:     "Empty password",
			password: "",
			wantErr:  true, // bcrypt can hash empty strings!
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := auth.HashPassword(tt.password)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, hash)

			err = auth.ComparePasswordAndHash(tt.password, hash)
			assert.NoError(t, err)
		})
	}
}

func TestComparePasswordAndHash(t *testing.T) {
	// Create a known password hash
	password := "testPassword123!"
	hash, err := auth.HashPassword(password)
	assert.NoError(t, err)

	tests := []struct {
		name     string
		password string
		hash     string
		wantErr  bool
	}{
		{
			name:     "Matching password",
			password: password,
			hash:     hash,
			wantErr:  false,
		},
		{
			name:     "Wrong password",
			password: "wrongPassword",
			hash:     hash,
			wantErr:  true,
		},
		{
			name:     "Invalid hash",
			password: password,
			hash:     "invalidhash",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.ComparePasswordAndHash(tt.password, tt.hash)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.hash == hash {
					assert.Equal(t, auth.ErrMismatchedHashAndPassword, err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRandomPasswordHash(t *testing.T) {
	hash1 := auth.RandomPasswordHash()
	hash2 := auth.RandomPasswordHash()

	assert.NotEmpty(t, hash1)
	assert.NotEmpty(t, hash2)
	assert.NotEqual(t, hash1, hash2)
}
