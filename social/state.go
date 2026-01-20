package social

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// StateManager handles OAuth state encoding and verification.
type StateManager interface {
	Encode(state *OAuthState) (string, error)
	Decode(token string) (*OAuthState, error)
}

// OAuthState contains the data stored in the OAuth state parameter.
type OAuthState struct {
	Nonce        string `json:"n"`
	Provider     string `json:"p"`
	CodeVerifier string `json:"cv,omitempty"`
	RedirectURL  string `json:"r,omitempty"`
	Action       string `json:"a"`
	LinkUserID   string `json:"lu,omitempty"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
}

// EncryptedStateManager uses AES-GCM encryption and HMAC signing.
type EncryptedStateManager struct {
	encryptionKey []byte
	hmacKey       []byte
	ttl           time.Duration
}

// NewEncryptedStateManager creates a new encrypted state manager.
func NewEncryptedStateManager(encryptionKey, hmacKey []byte, ttl time.Duration) *EncryptedStateManager {
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	return &EncryptedStateManager{
		encryptionKey: encryptionKey,
		hmacKey:       hmacKey,
		ttl:           ttl,
	}
}

// Encode encrypts and signs the state.
func (sm *EncryptedStateManager) Encode(state *OAuthState) (string, error) {
	if state == nil {
		return "", ErrInvalidState
	}

	if state.IssuedAt == 0 {
		state.IssuedAt = time.Now().Unix()
	}
	if state.ExpiresAt == 0 {
		state.ExpiresAt = time.Now().Add(sm.ttl).Unix()
	}

	if state.Nonce == "" {
		state.Nonce = generateNonce()
	}

	plaintext, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("failed to marshal state: %w", err)
	}

	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	mac := hmac.New(sha256.New, sm.hmacKey)
	mac.Write(ciphertext)
	signature := mac.Sum(nil)

	result := append(signature, ciphertext...)

	return base64.URLEncoding.EncodeToString(result), nil
}

// Decode verifies and decrypts the state.
func (sm *EncryptedStateManager) Decode(token string) (*OAuthState, error) {
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	if len(data) < sha256.Size {
		return nil, ErrInvalidState
	}

	signature := data[:sha256.Size]
	ciphertext := data[sha256.Size:]

	mac := hmac.New(sha256.New, sm.hmacKey)
	mac.Write(ciphertext)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(signature, expectedMAC) {
		return nil, ErrInvalidState
	}

	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidState
	}

	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, ErrInvalidState
	}

	var state OAuthState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	if time.Now().Unix() > state.ExpiresAt {
		return nil, ErrStateExpired
	}

	return &state, nil
}

func generateNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func computeCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
