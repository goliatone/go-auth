package oidc

import (
	"context"
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
	if provider.TokenEndpointAuthMethod != TokenEndpointAuthUnspecified {
		if _, authMethodErr := resolveTokenEndpointAuthMethod(provider, metadata); authMethodErr != nil {
			return nil, authMethodErr
		}
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
	if err := provider.validate(); err != nil {
		return DiscoveryMetadata{}, err
	}
	client = noRedirectHTTPClient(client)

	discoveryURL, err := discoveryURL(provider)
	if err != nil {
		return DiscoveryMetadata{}, err
	}

	requestCtx, cancel := providerRequestContext(ctx, provider.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return DiscoveryMetadata{}, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"cause": "request construction failed"})
	}

	res, err := client.Do(req)
	if err != nil {
		return DiscoveryMetadata{}, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"cause": "provider request failed"})
	}
	defer closeBody(res.Body)

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return DiscoveryMetadata{}, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"status": res.StatusCode})
	}

	var metadata DiscoveryMetadata
	if err := decodeBoundedJSON(res.Body, provider.Limits.normalized().DiscoveryBodyBytes, &metadata); err != nil {
		return DiscoveryMetadata{}, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"cause": "invalid discovery response"})
	}

	if err := validateDiscoveryEndpoints(provider, metadata); err != nil {
		return DiscoveryMetadata{}, err
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
