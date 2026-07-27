package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	auth "github.com/goliatone/go-auth"
)

const oidcRedacted = "[REDACTED]"

func (p ProviderConfig) MarshalJSON() ([]byte, error) {
	return nil, auth.ErrSecretSerialization
}
func (p ProviderConfig) MarshalText() ([]byte, error) { return nil, auth.ErrSecretSerialization }

func (p ProviderConfig) String() string {
	return fmt.Sprintf("oidc.ProviderConfig{Key:%q Issuer:%q ClientID:%q ClientSecret:%s RedirectURL:%q}", p.Key, p.Issuer, p.ClientID, oidcRedacted, p.RedirectURL)
}

func (p ProviderConfig) GoString() string               { return p.String() }
func (p ProviderConfig) LogValue() slog.Value           { return slog.StringValue(p.String()) }
func (p ProviderConfig) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(p.String())) }

func (r TokenResponse) MarshalJSON() ([]byte, error) {
	return nil, auth.ErrSecretSerialization
}
func (r TokenResponse) MarshalText() ([]byte, error) { return nil, auth.ErrSecretSerialization }

func (r TokenResponse) String() string {
	return fmt.Sprintf("oidc.TokenResponse{AccessToken:%s IDToken:%s RefreshToken:%s TokenType:%q}", oidcRedacted, oidcRedacted, oidcRedacted, r.TokenType)
}

func (r TokenResponse) GoString() string               { return r.String() }
func (r TokenResponse) LogValue() slog.Value           { return slog.StringValue(r.String()) }
func (r TokenResponse) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(r.String())) }

func (r AuthorizationResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ProviderKey string `json:"provider_key"`
		ExpiresAt   any    `json:"expires_at"`
	}{r.ProviderKey, r.ExpiresAt})
}

func (r AuthorizationResponse) String() string {
	return fmt.Sprintf("oidc.AuthorizationResponse{ProviderKey:%q RedirectURL:%s State:%s Nonce:%s CodeVerifier:%s}", r.ProviderKey, oidcRedacted, oidcRedacted, oidcRedacted, oidcRedacted)
}

func (r AuthorizationResponse) GoString() string     { return r.String() }
func (r AuthorizationResponse) LogValue() slog.Value { return slog.StringValue(r.String()) }
func (r AuthorizationResponse) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(r.String()))
}

// HTTPRedirectURL is the safe adapter boundary for starting browser login.
func (r AuthorizationResponse) HTTPRedirectURL() string { return r.RedirectURL }

func (r CallbackRequest) String() string {
	return fmt.Sprintf("oidc.CallbackRequest{ProviderKey:%q Code:%s State:%s RedirectTo:%q}", r.ProviderKey, oidcRedacted, oidcRedacted, r.RedirectTo)
}

func (r CallbackRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ProviderKey string `json:"provider_key"`
		RedirectTo  string `json:"redirect_to,omitempty"`
	}{r.ProviderKey, r.RedirectTo})
}
func (r CallbackRequest) MarshalText() ([]byte, error) { return nil, auth.ErrSecretSerialization }

func (r CallbackRequest) GoString() string               { return r.String() }
func (r CallbackRequest) LogValue() slog.Value           { return slog.StringValue(r.String()) }
func (r CallbackRequest) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(r.String())) }

func (r StateRecord) String() string {
	return fmt.Sprintf("oidc.StateRecord{State:%s Nonce:%s CodeVerifier:%s ProviderKey:%q RedirectTo:%q}", oidcRedacted, oidcRedacted, oidcRedacted, r.ProviderKey, r.RedirectTo)
}

func (r StateRecord) MarshalJSON() ([]byte, error) { return nil, auth.ErrSecretSerialization }
func (r StateRecord) MarshalText() ([]byte, error) { return nil, auth.ErrSecretSerialization }

func (r StateRecord) GoString() string               { return r.String() }
func (r StateRecord) LogValue() slog.Value           { return slog.StringValue(r.String()) }
func (r StateRecord) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(r.String())) }

func (r BrowserSessionResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ProviderKey    string           `json:"provider_key"`
		RedirectTarget string           `json:"redirect_target"`
		Identity       ExternalIdentity `json:"identity"`
		Audit          AuditMetadata    `json:"audit"`
	}{r.ProviderKey, r.RedirectTarget, r.Identity, r.Audit})
}
func (r BrowserSessionResult) MarshalText() ([]byte, error) {
	return nil, auth.ErrSecretSerialization
}

func (r BrowserSessionResult) String() string {
	return fmt.Sprintf("oidc.BrowserSessionResult{ProviderKey:%q RedirectTarget:%q LocalToken:%s HostSession:%s}", r.ProviderKey, r.RedirectTarget, oidcRedacted, oidcRedacted)
}

func (r BrowserSessionResult) GoString() string               { return r.String() }
func (r BrowserSessionResult) LogValue() slog.Value           { return slog.StringValue(r.String()) }
func (r BrowserSessionResult) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(r.String())) }

// SessionSecret returns the one browser cookie value without exposing provider
// tokens. It rejects missing and ambiguous callback results.
func (r BrowserSessionResult) SessionSecret() (auth.Secret, error) {
	if !r.HostSession.IsZero() {
		if r.LocalToken != "" {
			return auth.Secret{}, errors.New("oidc: callback result contains multiple session values")
		}
		return r.HostSession, nil
	}
	if r.LocalToken == "" {
		return auth.Secret{}, errors.New("oidc: callback result contains no session value")
	}
	return auth.NewSecret(r.LocalToken), nil
}

func (r ProviderSessionHandoffResult) MarshalJSON() ([]byte, error) {
	return nil, auth.ErrSecretSerialization
}
func (r ProviderSessionHandoffResult) MarshalText() ([]byte, error) {
	return nil, auth.ErrSecretSerialization
}
func (r ProviderSessionHandoffResult) String() string {
	return fmt.Sprintf("oidc.ProviderSessionHandoffResult{HostSession:%s LocalSessionID:%q}", oidcRedacted, r.localSessionID)
}
func (r ProviderSessionHandoffResult) GoString() string     { return r.String() }
func (r ProviderSessionHandoffResult) LogValue() slog.Value { return slog.StringValue(r.String()) }
func (r ProviderSessionHandoffResult) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(r.String()))
}
