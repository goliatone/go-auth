package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	TokenEnvelopeVersion1  = uint8(1)
	TokenEnvelopeAES256GCM = "AES-256-GCM" // #nosec G101 -- Algorithm identifier, not a credential.
)

type AESGCMTokenCipher struct {
	keys TokenKeyProvider
	rand io.Reader
}

func NewAESGCMTokenCipher(keys TokenKeyProvider) (*AESGCMTokenCipher, error) {
	if keys == nil {
		return nil, fmt.Errorf("%w: key provider is required", ErrProviderTokenCipher)
	}
	return &AESGCMTokenCipher{keys: keys, rand: rand.Reader}, nil
}

func (c *AESGCMTokenCipher) Seal(ctx context.Context, plaintext, associatedData []byte) (TokenEnvelope, error) {
	if c == nil || c.keys == nil || len(plaintext) == 0 || len(plaintext) > MaxProviderTokenPayloadBytes || len(associatedData) == 0 {
		return TokenEnvelope{}, ErrProviderTokenEnvelope
	}
	key, err := c.keys.ActiveKey(ctx)
	if err != nil {
		return TokenEnvelope{}, fmt.Errorf("%w: active key unavailable", ErrProviderTokenKeyNotFound)
	}
	if key.Retired() {
		return TokenEnvelope{}, ErrProviderTokenKeyRetired
	}
	aead, err := tokenAEAD(key)
	if err != nil {
		return TokenEnvelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(c.rand, nonce); err != nil {
		return TokenEnvelope{}, fmt.Errorf("%w: nonce source unavailable", ErrProviderTokenCipher)
	}
	return TokenEnvelope{
		Version:    TokenEnvelopeVersion1,
		Algorithm:  TokenEnvelopeAES256GCM,
		KeyID:      key.ID(),
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, associatedData),
	}, nil
}

//nolint:gocyclo // Envelope and key invariants are validated explicitly before decryption.
func (c *AESGCMTokenCipher) Open(ctx context.Context, envelope TokenEnvelope, associatedData []byte) ([]byte, error) {
	if c == nil || c.keys == nil || len(associatedData) == 0 ||
		envelope.Version != TokenEnvelopeVersion1 ||
		envelope.Algorithm != TokenEnvelopeAES256GCM ||
		strings.TrimSpace(envelope.KeyID) == "" ||
		len(envelope.KeyID) > MaxProviderTokenKeyIDBytes ||
		len(envelope.Ciphertext) == 0 ||
		len(envelope.Ciphertext) > MaxProviderTokenPayloadBytes+32 {
		return nil, ErrProviderTokenEnvelope
	}
	key, err := c.keys.Key(ctx, envelope.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: key unavailable", ErrProviderTokenKeyNotFound)
	}
	aead, err := tokenAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(envelope.Nonce) != aead.NonceSize() {
		return nil, ErrProviderTokenEnvelope
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, associatedData)
	if err != nil {
		return nil, ErrProviderTokenCipher
	}
	if len(plaintext) == 0 || len(plaintext) > MaxProviderTokenPayloadBytes {
		return nil, ErrProviderTokenEnvelope
	}
	return plaintext, nil
}

func tokenAEAD(key TokenEncryptionKey) (cipher.AEAD, error) {
	if strings.TrimSpace(key.ID()) == "" || len(key.Material()) != 32 {
		return nil, ErrProviderTokenKeyNotFound
	}
	block, err := aes.NewCipher(key.Material())
	if err != nil {
		return nil, ErrProviderTokenCipher
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrProviderTokenCipher
	}
	return aead, nil
}

type StaticTokenKeyProvider struct {
	mu       sync.RWMutex
	activeID string
	keys     map[string]TokenEncryptionKey
}

func NewStaticTokenKeyProvider(activeID string, keys ...TokenEncryptionKey) (*StaticTokenKeyProvider, error) {
	provider := &StaticTokenKeyProvider{keys: make(map[string]TokenEncryptionKey, len(keys))}
	for _, key := range keys {
		if key.ID() == "" || len(key.Material()) != 32 {
			return nil, ErrProviderTokenKeyNotFound
		}
		if _, exists := provider.keys[key.ID()]; exists {
			return nil, ErrProviderTokenKeyNotFound
		}
		provider.keys[key.ID()] = key
	}
	activeID = strings.TrimSpace(activeID)
	active, ok := provider.keys[activeID]
	if !ok {
		return nil, ErrProviderTokenKeyNotFound
	}
	if active.Retired() {
		return nil, ErrProviderTokenKeyRetired
	}
	provider.activeID = activeID
	return provider, nil
}

func (p *StaticTokenKeyProvider) ActiveKey(context.Context) (TokenEncryptionKey, error) {
	if p == nil {
		return TokenEncryptionKey{}, ErrProviderTokenKeyNotFound
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	key, ok := p.keys[p.activeID]
	if !ok {
		return TokenEncryptionKey{}, ErrProviderTokenKeyNotFound
	}
	if key.Retired() {
		return TokenEncryptionKey{}, ErrProviderTokenKeyRetired
	}
	return cloneTokenEncryptionKey(key), nil
}

func (p *StaticTokenKeyProvider) Key(_ context.Context, keyID string) (TokenEncryptionKey, error) {
	if p == nil {
		return TokenEncryptionKey{}, ErrProviderTokenKeyNotFound
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	key, ok := p.keys[strings.TrimSpace(keyID)]
	if !ok {
		return TokenEncryptionKey{}, ErrProviderTokenKeyNotFound
	}
	return cloneTokenEncryptionKey(key), nil
}

func (p *StaticTokenKeyProvider) Rotate(active TokenEncryptionKey) error {
	if p == nil || active.ID() == "" || len(active.Material()) != 32 {
		return ErrProviderTokenKeyNotFound
	}
	if active.Retired() {
		return ErrProviderTokenKeyRetired
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[active.ID()] = cloneTokenEncryptionKey(active)
	p.activeID = active.ID()
	return nil
}

func (p *StaticTokenKeyProvider) Retire(keyID string) error {
	if p == nil {
		return ErrProviderTokenKeyNotFound
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key, ok := p.keys[strings.TrimSpace(keyID)]
	if !ok {
		return ErrProviderTokenKeyNotFound
	}
	if key.ID() == p.activeID {
		return ErrProviderTokenKeyRetired
	}
	key.retired = true
	p.keys[key.ID()] = key
	return nil
}

func cloneTokenEncryptionKey(key TokenEncryptionKey) TokenEncryptionKey {
	return TokenEncryptionKey{
		id: key.id, material: append([]byte(nil), key.material...), retired: key.retired,
	}
}

var (
	_ TokenCipher      = (*AESGCMTokenCipher)(nil)
	_ TokenKeyProvider = (*StaticTokenKeyProvider)(nil)
)
