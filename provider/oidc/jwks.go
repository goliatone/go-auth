package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
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
	uri             string
	ttl             time.Duration
	client          *http.Client
	limits          Limits
	requestTimeout  time.Duration
	refreshCooldown time.Duration
	clock           func() time.Time
	mu              sync.RWMutex
	keys            map[string]jwk
	expiresAt       time.Time
	generation      uint64
	lastMissRefresh time.Time
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

const (
	minRSAModulusBits = 2048
	maxRSAModulusBits = 16384
)

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

func newJWKSCache(
	uri string,
	ttl time.Duration,
	refreshCooldown time.Duration,
	client *http.Client,
	limits Limits,
	requestTimeout time.Duration,
	clock func() time.Time,
) *jwksCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if refreshCooldown <= 0 {
		refreshCooldown = 30 * time.Second
	}
	if client == nil {
		client = http.DefaultClient
	}
	if clock == nil {
		clock = time.Now
	}
	return &jwksCache{
		uri: uri, ttl: ttl, refreshCooldown: refreshCooldown,
		client: noRedirectHTTPClient(client), limits: limits.normalized(),
		requestTimeout: requestTimeout, clock: clock,
	}
}

func (c *jwksCache) key(ctx context.Context, kid string) (jwk, bool, error) {
	keys, generation, err := c.snapshot(ctx, false)
	if err != nil {
		return jwk{}, false, err
	}
	if key, ok := keys[kid]; ok {
		return key, true, nil
	}

	keys, err = c.refreshForUnknownKey(ctx, generation)
	if err != nil {
		return jwk{}, false, err
	}
	key, ok := keys[kid]
	return key, ok, nil
}

func (c *jwksCache) keysSnapshot(ctx context.Context, force bool) (map[string]jwk, error) {
	keys, _, err := c.snapshot(ctx, force)
	return keys, err
}

func (c *jwksCache) snapshot(ctx context.Context, force bool) (map[string]jwk, uint64, error) {
	now := c.clock()
	c.mu.RLock()
	if !force && len(c.keys) > 0 && now.Before(c.expiresAt) {
		keys := cloneJWKMap(c.keys)
		generation := c.generation
		c.mu.RUnlock()
		return keys, generation, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && len(c.keys) > 0 && c.clock().Before(c.expiresAt) {
		return cloneJWKMap(c.keys), c.generation, nil
	}

	keys, err := c.fetch(ctx)
	if err != nil {
		return nil, c.generation, err
	}
	c.keys = keys
	c.expiresAt = c.clock().Add(c.ttl)
	c.generation++
	return cloneJWKMap(c.keys), c.generation, nil
}

func (c *jwksCache) refreshForUnknownKey(ctx context.Context, observedGeneration uint64) (map[string]jwk, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.generation != observedGeneration {
		return cloneJWKMap(c.keys), nil
	}
	now := c.clock()
	if !c.lastMissRefresh.IsZero() && now.Sub(c.lastMissRefresh) < c.refreshCooldown {
		return cloneJWKMap(c.keys), nil
	}
	// Record the attempt before I/O so failures are also throttled.
	c.lastMissRefresh = now
	keys, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}
	c.keys = keys
	c.expiresAt = c.clock().Add(c.ttl)
	c.generation++
	return cloneJWKMap(c.keys), nil
}

func (c *jwksCache) fetch(ctx context.Context) (map[string]jwk, error) {
	requestCtx, cancel := providerRequestContext(ctx, c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, c.uri, nil)
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
	if err := decodeBoundedJSON(res.Body, c.limits.JWKSBodyBytes, &doc); err != nil {
		return nil, err
	}
	if len(doc.Keys) > c.limits.JWKSKeys {
		return nil, fmt.Errorf("jwks has %d keys; limit is %d", len(doc.Keys), c.limits.JWKSKeys)
	}
	keys := make(map[string]jwk, len(doc.Keys))
	for _, key := range doc.Keys {
		if strings.TrimSpace(key.KeyID) == "" {
			return nil, fmt.Errorf("jwks key is missing kid")
		}
		if _, exists := keys[key.KeyID]; exists {
			return nil, fmt.Errorf("jwks contains duplicate kid")
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
	if k.KeyType != "RSA" {
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
	if len(eBytes) == 0 || len(eBytes) > 4 {
		return nil, fmt.Errorf("invalid rsa exponent")
	}
	var exponent uint64
	for _, b := range eBytes {
		exponent = exponent<<8 + uint64(b)
	}
	if exponent < 3 || exponent > 1<<31-1 || exponent%2 == 0 {
		return nil, fmt.Errorf("invalid rsa exponent")
	}
	n := new(big.Int).SetBytes(nBytes)
	if n.Sign() <= 0 || n.BitLen() < minRSAModulusBits || n.BitLen() > maxRSAModulusBits {
		return nil, fmt.Errorf("invalid rsa modulus")
	}
	return &rsa.PublicKey{N: n, E: int(exponent)}, nil
}

func (k jwk) ecPublicKey() (*ecdsa.PublicKey, error) {
	if k.KeyType != "EC" {
		return nil, fmt.Errorf("unsupported key type %q", k.KeyType)
	}
	if k.Curve != "P-256" {
		return nil, fmt.Errorf("unsupported elliptic curve %q", k.Curve)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(xBytes) != 32 {
		return nil, fmt.Errorf("invalid ec x coordinate")
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil || len(yBytes) != 32 {
		return nil, fmt.Errorf("invalid ec y coordinate")
	}
	encoded := make([]byte, 1+len(xBytes)+len(yBytes))
	encoded[0] = 4
	copy(encoded[1:], xBytes)
	copy(encoded[1+len(xBytes):], yBytes)
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid P-256 public key: %w", err)
	}
	return key, nil
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
