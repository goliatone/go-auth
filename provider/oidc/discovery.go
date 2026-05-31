package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func NewProvider(ctx context.Context, provider ProviderConfig, opts ...ProviderOption) (*Provider, error) {
	if err := provider.validate(); err != nil {
		return nil, err
	}

	options := providerOptions{httpClient: http.DefaultClient}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.httpClient == nil {
		options.httpClient = http.DefaultClient
	}

	metadata, err := Discover(ctx, provider, options.httpClient)
	if err != nil {
		return nil, err
	}

	validator, err := NewTokenValidator(ctx, provider, metadata, WithValidatorHTTPClient(options.httpClient))
	if err != nil {
		return nil, err
	}

	return &Provider{
		Config:    provider,
		Metadata:  metadata,
		Validator: validator,
	}, nil
}

type ProviderOption func(*providerOptions)

type providerOptions struct {
	httpClient *http.Client
}

func WithProviderHTTPClient(client *http.Client) ProviderOption {
	return func(opts *providerOptions) {
		if opts != nil && client != nil {
			opts.httpClient = client
		}
	}
}

func Discover(ctx context.Context, provider ProviderConfig, client *http.Client) (DiscoveryMetadata, error) {
	if client == nil {
		client = http.DefaultClient
	}

	discoveryURL, err := discoveryURL(provider)
	if err != nil {
		return DiscoveryMetadata{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return DiscoveryMetadata{}, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"cause": err.Error()})
	}

	res, err := client.Do(req)
	if err != nil {
		return DiscoveryMetadata{}, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"cause": err.Error()})
	}
	defer res.Body.Close()

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return DiscoveryMetadata{}, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"status": res.StatusCode})
	}

	var metadata DiscoveryMetadata
	if err := json.NewDecoder(res.Body).Decode(&metadata); err != nil {
		return DiscoveryMetadata{}, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"cause": err.Error()})
	}

	if strings.TrimSpace(metadata.Issuer) == "" {
		return DiscoveryMetadata{}, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"field": "issuer"})
	}
	if strings.TrimSpace(metadata.JWKSURI) == "" {
		return DiscoveryMetadata{}, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"field": "jwks_uri"})
	}
	if provider.Issuer != "" && strings.TrimRight(metadata.Issuer, "/") != strings.TrimRight(provider.Issuer, "/") {
		return DiscoveryMetadata{}, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{
			"field": "issuer",
			"want":  provider.Issuer,
			"got":   metadata.Issuer,
		})
	}

	return metadata, nil
}

func discoveryURL(provider ProviderConfig) (string, error) {
	if raw := strings.TrimSpace(provider.DiscoveryURL); raw != "" {
		return raw, nil
	}

	issuer := strings.TrimSpace(provider.Issuer)
	if issuer == "" {
		return "", cloneWithProvider(ErrInvalidConfig, provider.Key, map[string]any{"field": "issuer"})
	}

	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", cloneWithProvider(ErrInvalidConfig, provider.Key, map[string]any{"field": "issuer", "value": issuer})
	}

	path := strings.TrimRight(parsed.Path, "/")
	parsed.Path = fmt.Sprintf("%s/.well-known/openid-configuration", path)
	return parsed.String(), nil
}
