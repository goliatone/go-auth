package auth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestSecretFailsClosedAcrossFormattingAndSerialization(t *testing.T) {
	const canary = "secret-canary-token"
	secret := NewSecret(canary)
	for _, formatted := range []string{
		fmt.Sprint(secret), fmt.Sprintf("%s", secret), fmt.Sprintf("%v", secret),
		fmt.Sprintf("%+v", secret), fmt.Sprintf("%#v", secret), secret.LogValue().String(),
	} {
		if strings.Contains(formatted, canary) || !strings.Contains(formatted, redactedSecret) {
			t.Fatalf("unsafe secret formatting %q", formatted)
		}
	}
	if _, err := json.Marshal(secret); err == nil {
		t.Fatal("expected JSON serialization to fail")
	}
	if _, err := secret.MarshalText(); err == nil {
		t.Fatal("expected text serialization to fail")
	}
	var decoded Secret
	if err := decoded.UnmarshalText([]byte(canary)); err == nil {
		t.Fatal("expected text deserialization to fail")
	}
	if secret.Reveal() != canary || secret.IsZero() {
		t.Fatal("explicit secret reveal failed")
	}
	if !NewSecret("").IsZero() {
		t.Fatal("empty secret should be zero")
	}
	_ = slog.Any("secret", secret)
}

func TestProviderTokenSetCopiesTypedContextAndRedacts(t *testing.T) {
	now := time.Now().UTC()
	methods := []string{"pwd"}
	set, err := NewProviderTokenSet(ProviderTokenSetInput{
		AccessToken:     NewSecret("access-canary"),
		IDToken:         NewSecret("id-canary"),
		TokenType:       "Bearer",
		Scopes:          []string{"openid", "profile", "openid"},
		AcquiredAt:      now,
		AccessExpiresAt: now.Add(time.Hour),
		IDContext: &ValidatedTokenContext{
			Issuer: "https://issuer.example", Subject: "provider-user",
			AssuranceMethods: methods,
		},
		Metadata: map[string]string{"flow": "browser"},
	})
	if err != nil {
		t.Fatal(err)
	}
	methods[0] = "mutated"
	context, ok := set.IDContext()
	if !ok || context.AssuranceMethods[0] != "pwd" {
		t.Fatalf("context was not defensively copied: %+v", context)
	}
	if got := set.Scopes(); len(got) != 2 {
		t.Fatalf("scopes were not compacted: %v", got)
	}
	if set.AccessToken().Reveal() != "access-canary" {
		t.Fatal("access token unavailable to trusted caller")
	}
	for _, output := range []string{fmt.Sprint(set), fmt.Sprintf("%+v", set), set.LogValue().String()} {
		if strings.Contains(output, "canary") {
			t.Fatalf("token set leaked: %s", output)
		}
	}
	if _, err := json.Marshal(set); err == nil {
		t.Fatal("expected token set JSON serialization to fail")
	}
}

func TestProviderContractsRejectInvalidAndOversizedMetadata(t *testing.T) {
	if _, err := NewProviderTokenSet(ProviderTokenSetInput{}); err == nil {
		t.Fatal("expected empty token set rejection")
	}
	oversized := map[string]string{}
	for i := 0; i <= DefaultPrincipalMetadataEntries; i++ {
		oversized[fmt.Sprintf("key-%d", i)] = "value"
	}
	if _, err := NewProviderTokenSet(ProviderTokenSetInput{AccessToken: NewSecret("x"), Metadata: oversized}); err == nil {
		t.Fatal("expected oversized token metadata rejection")
	}
	if _, err := NewAuthenticatedPrincipal(AuthenticatedPrincipalInput{}); err == nil {
		t.Fatal("expected incomplete principal rejection")
	}
	principal, err := NewAuthenticatedPrincipal(AuthenticatedPrincipalInput{
		ApplicationSubject: "local-user",
		Provider:           "oidc",
		ProviderSubject:    "provider-user",
		AssuranceMethods:   []string{"pwd"},
		Metadata:           map[string]string{"profile": "limited"},
	})
	if err != nil {
		t.Fatal(err)
	}
	clone := principal.Clone()
	methods := clone.AssuranceMethods()
	methods[0] = "mutated"
	if principal.AssuranceMethods()[0] != "pwd" {
		t.Fatal("principal clone aliased assurance methods")
	}
	bound, err := principal.BindLocalSessionID("local-session")
	if err != nil {
		t.Fatal(err)
	}
	if bound.LocalSessionID() != "local-session" || principal.LocalSessionID() != "" {
		t.Fatalf("local session binding mutated the original: original=%q bound=%q", principal.LocalSessionID(), bound.LocalSessionID())
	}
	if _, err := bound.BindLocalSessionID("different-session"); err == nil {
		t.Fatal("expected local session rebinding rejection")
	}
	if _, err := principal.BindLocalSessionID(""); err == nil {
		t.Fatal("expected empty local session rejection")
	}
}
