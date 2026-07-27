package social

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const MaxProviderResponseBytes int64 = 1 << 20

func ValidateProviderEndpoint(raw string, allowInsecureLoopback bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("social: invalid provider endpoint")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(parsed.Hostname())
	loopback := parsed.Hostname() == "localhost" || ip != nil && ip.IsLoopback()
	if parsed.Scheme == "http" && allowInsecureLoopback && loopback {
		return nil
	}
	return fmt.Errorf("social: provider endpoint must use HTTPS")
}

func HardenProviderHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	if clone.Timeout <= 0 {
		clone.Timeout = 10 * time.Second
	}
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}

func ReadProviderResponseBody(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, errors.New("social: provider response body is missing")
	}
	payload, err := io.ReadAll(io.LimitReader(body, MaxProviderResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > MaxProviderResponseBytes {
		return nil, errors.New("social: provider response body exceeds limit")
	}
	return payload, nil
}
