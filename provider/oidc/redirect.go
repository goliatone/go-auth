package oidc

import (
	"net/url"
	"strings"
)

func SafeRedirect(raw string, fallback string, allowedOrigins []string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = strings.TrimSpace(fallback)
	}
	if raw == "" {
		raw = "/"
	}
	if strings.Contains(raw, "\\") {
		return "", ErrUnsafeRedirect
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", ErrUnsafeRedirect
	}
	if !parsed.IsAbs() {
		if strings.HasPrefix(raw, "//") || !strings.HasPrefix(parsed.Path, "/") {
			return "", ErrUnsafeRedirect
		}
		return parsed.String(), nil
	}

	origin := parsed.Scheme + "://" + parsed.Host
	for _, allowed := range allowedOrigins {
		if strings.TrimRight(strings.TrimSpace(allowed), "/") == origin {
			return parsed.String(), nil
		}
	}
	return "", ErrUnsafeRedirect
}
