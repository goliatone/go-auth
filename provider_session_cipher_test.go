package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAESGCMTokenCipherRoundTripAndNonceUniqueness(t *testing.T) {
	t.Parallel()
	key, err := NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	cipher, err := NewAESGCMTokenCipher(keys)
	require.NoError(t, err)

	plaintext := []byte("provider-token-material")
	aad := []byte("session-binding")
	first, err := cipher.Seal(context.Background(), plaintext, aad)
	require.NoError(t, err)
	second, err := cipher.Seal(context.Background(), plaintext, aad)
	require.NoError(t, err)
	require.NotEqual(t, first.Nonce, second.Nonce)
	require.NotEqual(t, first.Ciphertext, second.Ciphertext)

	opened, err := cipher.Open(context.Background(), first, aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)
}

func TestAESGCMTokenCipherFailsClosed(t *testing.T) {
	t.Parallel()
	key, err := NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	cipher, err := NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	envelope, err := cipher.Seal(context.Background(), []byte("secret"), []byte("aad"))
	require.NoError(t, err)

	_, err = cipher.Open(context.Background(), envelope, []byte("wrong-aad"))
	require.ErrorIs(t, err, ErrProviderTokenCipher)
	corrupt := envelope
	corrupt.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	corrupt.Ciphertext[0] ^= 0xff
	_, err = cipher.Open(context.Background(), corrupt, []byte("aad"))
	require.ErrorIs(t, err, ErrProviderTokenCipher)
	corrupt = envelope
	corrupt.Version = 2
	_, err = cipher.Open(context.Background(), corrupt, []byte("aad"))
	require.ErrorIs(t, err, ErrProviderTokenEnvelope)
	corrupt = envelope
	corrupt.KeyID = "missing"
	_, err = cipher.Open(context.Background(), corrupt, []byte("aad"))
	require.ErrorIs(t, err, ErrProviderTokenKeyNotFound)
}

func TestTokenCipherSecretsAreRedacted(t *testing.T) {
	t.Parallel()
	key, err := NewTokenEncryptionKey("key-1", []byte("01234567890123456789012345678901"), false)
	require.NoError(t, err)
	require.NotContains(t, fmt.Sprintf("%v %#v", key, key), "0123456789")
	_, err = json.Marshal(key)
	require.ErrorIs(t, err, ErrSecretSerialization)

	envelope := TokenEnvelope{Version: 1, Algorithm: TokenEnvelopeAES256GCM, KeyID: "key-1", Ciphertext: []byte("secret")}
	require.NotContains(t, fmt.Sprintf("%v %#v", envelope, envelope), "secret")
	_, err = json.Marshal(envelope)
	require.ErrorIs(t, err, ErrSecretSerialization)
}

func TestStaticTokenKeyProviderRotationKeepsRetiredKeysReadable(t *testing.T) {
	t.Parallel()
	oldKey, err := NewTokenEncryptionKey("old", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := NewStaticTokenKeyProvider("old", oldKey)
	require.NoError(t, err)
	cipher, err := NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	oldEnvelope, err := cipher.Seal(context.Background(), []byte("tokens"), []byte("aad"))
	require.NoError(t, err)

	newKey, err := NewTokenEncryptionKey("new", []byte("11111111111111111111111111111111"), false)
	require.NoError(t, err)
	require.NoError(t, keys.Rotate(newKey))
	require.NoError(t, keys.Retire("old"))

	opened, err := cipher.Open(context.Background(), oldEnvelope, []byte("aad"))
	require.NoError(t, err)
	require.Equal(t, []byte("tokens"), opened)
	newEnvelope, err := cipher.Seal(context.Background(), []byte("tokens"), []byte("aad"))
	require.NoError(t, err)
	require.Equal(t, "new", newEnvelope.KeyID)
	require.ErrorIs(t, keys.Retire("new"), ErrProviderTokenKeyRetired)
}
