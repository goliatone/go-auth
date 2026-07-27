package social

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProviderTransportSecurityPolicy(t *testing.T) {
	require.NoError(t, ValidateProviderEndpoint("https://provider.example/token", false))
	require.Error(t, ValidateProviderEndpoint("http://provider.example/token", true))
	require.Error(t, ValidateProviderEndpoint("http://127.0.0.1/token", false))
	require.NoError(t, ValidateProviderEndpoint("http://127.0.0.1/token", true))

	client := HardenProviderHTTPClient(&http.Client{})
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "other.example"}}
	require.ErrorIs(t, client.CheckRedirect(req, nil), http.ErrUseLastResponse)

	_, err := ReadProviderResponseBody(strings.NewReader(strings.Repeat("x", int(MaxProviderResponseBytes)+1)))
	require.Error(t, err)
	body, err := ReadProviderResponseBody(bytes.NewBufferString(`{"ok":true}`))
	require.NoError(t, err)
	require.Equal(t, `{"ok":true}`, string(body))
}

func TestRedirectTargetPolicy(t *testing.T) {
	require.NoError(t, validateRedirectTarget("/dashboard", nil))
	require.Error(t, validateRedirectTarget("//evil.example/path", nil))
	require.Error(t, validateRedirectTarget("https://evil.example/path", nil))
	require.NoError(t, validateRedirectTarget("https://app.example/path", []string{"https://app.example"}))
}
