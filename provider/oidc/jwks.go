package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

type jwksCache struct {
	uri       string
	ttl       time.Duration
	client    *http.Client
	mu        sync.RWMutex
	keys      map[string]jwk
	expiresAt time.Time
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KeyID     string   `json:"kid"`
	KeyType   string   `json:"kty"`
	Algorithm string   `json:"alg,omitempty"`
	Use       string   `json:"use,omitempty"`
	KeyOps    []string `json:"key_ops,omitempty"`
	Modulus   string   `json:"n,omitempty"`
	Exponent  string   `json:"e,omitempty"`
	Curve     string   `json:"crv,omitempty"`
	X         string   `json:"x,omitempty"`
	Y         string   `json:"y,omitempty"`
}

func newJWKSCache(uri string, ttl time.Duration, client *http.Client) *jwksCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &jwksCache{uri: uri, ttl: ttl, client: client}
}

func (c *jwksCache) key(ctx context.Context, kid string) (jwk, bool, error) {
	keys, err := c.keysSnapshot(ctx, false)
	if err != nil {
		return jwk{}, false, err
	}
	if key, ok := keys[kid]; ok {
		return key, true, nil
	}

	keys, err = c.keysSnapshot(ctx, true)
	if err != nil {
		return jwk{}, false, err
	}
	key, ok := keys[kid]
	return key, ok, nil
}

func (c *jwksCache) keysSnapshot(ctx context.Context, force bool) (map[string]jwk, error) {
	now := time.Now()
	c.mu.RLock()
	if !force && len(c.keys) > 0 && now.Before(c.expiresAt) {
		keys := cloneJWKMap(c.keys)
		c.mu.RUnlock()
		return keys, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && len(c.keys) > 0 && time.Now().Before(c.expiresAt) {
		return cloneJWKMap(c.keys), nil
	}

	keys, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}
	c.keys = keys
	c.expiresAt = time.Now().Add(c.ttl)
	return cloneJWKMap(c.keys), nil
}

func (c *jwksCache) fetch(ctx context.Context) (map[string]jwk, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.uri, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer closeBody(res.Body)
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("jwks fetch failed with status %d", res.StatusCode)
	}

	var doc jwksDocument
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return nil, err
	}
	keys := make(map[string]jwk, len(doc.Keys))
	for _, key := range doc.Keys {
		if strings.TrimSpace(key.KeyID) == "" {
			continue
		}
		keys[key.KeyID] = key
	}
	return keys, nil
}

func cloneJWKMap(in map[string]jwk) map[string]jwk {
	out := make(map[string]jwk, len(in))
	maps.Copy(out, in)
	return out
}

func (k jwk) rsaPublicKey() (*rsa.PublicKey, error) {
	if !strings.EqualFold(k.KeyType, "RSA") {
		return nil, fmt.Errorf("unsupported key type %q", k.KeyType)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.Modulus)
	if err != nil {
		return nil, fmt.Errorf("invalid rsa modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.Exponent)
	if err != nil {
		return nil, fmt.Errorf("invalid rsa exponent: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e == 0 {
		return nil, fmt.Errorf("invalid rsa exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func (k jwk) allowsSigning() bool {
	if k.Use != "" && k.Use != "sig" {
		return false
	}
	if len(k.KeyOps) == 0 {
		return true
	}
	return slices.Contains(k.KeyOps, "verify")
}
