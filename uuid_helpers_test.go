package auth_test

import (
	"testing"

	"github.com/goliatone/go-auth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestHasUserUUID(t *testing.T) {
	t.Run("uuid subject", func(t *testing.T) {
		session := &auth.SessionObject{
			UserID: uuid.NewString(),
		}

		assert.True(t, auth.HasUserUUID(session))
	})

	t.Run("auth0 subject", func(t *testing.T) {
		session := &auth.SessionObject{
			UserID: "auth0|1234567890",
		}

		assert.False(t, auth.HasUserUUID(session))
	})

	t.Run("nil session", func(t *testing.T) {
		assert.False(t, auth.HasUserUUID(nil))
	})
}
