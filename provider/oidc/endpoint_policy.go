package oidc

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var reservedAuthorizationParameters = map[string]struct{}{
	"response_type":         {},
	"client_id":             {},
	"redirect_uri":          {},
	"scope":                 {},
	"state":                 {},
	"nonce":                 {},
	"code_challenge":        {},
	"code_challenge_method": {},
}

func isReservedAuthorizationParameter(name string) bool {
	_, reserved := reservedAuthorizationParameters[strings.ToLower(strings.TrimSpace(name))]
	return reserved
}

func validateProviderEndpoint(raw string, allowInsecureLoopback bool, issuer bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("invalid endpoint")
	}
	if parsed.Fragment != "" || (issuer && parsed.RawQuery != "") {
		return fmt.Errorf("invalid endpoint components")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if allowInsecureLoopback && isLoopbackHostname(parsed.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("insecure endpoint")
}

func isLoopbackHostname(host string) bool {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func noRedirectHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	cloned := *client
	cloned.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &cloned
}

func validateDiscoveryEndpoints(provider ProviderConfig, metadata DiscoveryMetadata) error {
	return validateEndpointSet(provider, []providerEndpoint{
		{field: "issuer", value: metadata.Issuer, required: true, issuer: true},
		{field: "authorization_endpoint", value: metadata.AuthorizationEndpoint, required: true},
		{field: "token_endpoint", value: metadata.TokenEndpoint, required: true},
		{field: "jwks_uri", value: metadata.JWKSURI, required: true},
		{field: "userinfo_endpoint", value: metadata.UserInfoEndpoint, required: provider.UserInfo},
		{field: "end_session_endpoint", value: metadata.EndSessionEndpoint},
	})
}

func validateTokenValidationEndpoints(provider ProviderConfig, metadata DiscoveryMetadata) error {
	return validateEndpointSet(provider, []providerEndpoint{
		{field: "issuer", value: metadata.Issuer, required: true, issuer: true},
		{field: "jwks_uri", value: metadata.JWKSURI, required: true},
	})
}

type providerEndpoint struct {
	field    string
	value    string
	required bool
	issuer   bool
}

func validateEndpointSet(provider ProviderConfig, endpoints []providerEndpoint) error {
	for _, endpoint := range endpoints {
		if strings.TrimSpace(endpoint.value) == "" {
			if endpoint.required {
				return cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"field": endpoint.field})
			}
			continue
		}
		if err := validateProviderEndpoint(endpoint.value, provider.AllowInsecureHTTP, endpoint.issuer); err != nil {
			return cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{
				"field": endpoint.field,
				"cause": "endpoint must use HTTPS or explicit loopback HTTP",
			})
		}
	}
	return nil
}
