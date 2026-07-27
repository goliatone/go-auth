package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const (
	DefaultDocumentBodyBytes  int64 = 1 << 20
	DefaultTokenBodyBytes     int64 = 256 << 10
	DefaultEncodedTokenBytes        = 64 << 10
	DefaultCallbackCodeBytes        = 8 << 10
	DefaultCallbackStateBytes       = 1 << 10
	DefaultRedirectBytes            = 8 << 10
	DefaultProviderKeyBytes         = 128
	DefaultJWKSKeys                 = 100
	DefaultRequestTimeout           = 10 * time.Second
)

func closeBody(body io.Closer) {
	_ = body.Close()
}

func (l Limits) normalized() Limits {
	if l.DiscoveryBodyBytes <= 0 {
		l.DiscoveryBodyBytes = DefaultDocumentBodyBytes
	}
	if l.JWKSBodyBytes <= 0 {
		l.JWKSBodyBytes = DefaultDocumentBodyBytes
	}
	if l.UserInfoBodyBytes <= 0 {
		l.UserInfoBodyBytes = DefaultDocumentBodyBytes
	}
	if l.TokenBodyBytes <= 0 {
		l.TokenBodyBytes = DefaultTokenBodyBytes
	}
	if l.EncodedTokenBytes <= 0 {
		l.EncodedTokenBytes = DefaultEncodedTokenBytes
	}
	if l.CallbackCodeBytes <= 0 {
		l.CallbackCodeBytes = DefaultCallbackCodeBytes
	}
	if l.CallbackStateBytes <= 0 {
		l.CallbackStateBytes = DefaultCallbackStateBytes
	}
	if l.RedirectBytes <= 0 {
		l.RedirectBytes = DefaultRedirectBytes
	}
	if l.ProviderKeyBytes <= 0 {
		l.ProviderKeyBytes = DefaultProviderKeyBytes
	}
	if l.JWKSKeys <= 0 {
		l.JWKSKeys = DefaultJWKSKeys
	}
	return l
}

func providerRequestContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= timeout {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func decodeBoundedJSON(body io.Reader, maxBytes int64, target any) error {
	if maxBytes <= 0 {
		return fmt.Errorf("invalid response size limit")
	}
	limited := &io.LimitedReader{R: body, N: maxBytes + 1}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	if limited.N == 0 {
		return fmt.Errorf("response exceeds %d bytes", maxBytes)
	}
	return nil
}

func validateEncodedTokenSize(raw string, limit int) error {
	if len(raw) > limit {
		return fmt.Errorf("encoded token exceeds %d bytes", limit)
	}
	return nil
}
