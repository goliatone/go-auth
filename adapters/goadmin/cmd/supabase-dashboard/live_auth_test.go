package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/google/uuid"
)

// Local-token mode uses the same issued session contract as the OIDC callback.
// Discovery/JWKS are a deterministic fixture; this is not a live Supabase login.
func TestDashboardLiveLocalSession(t *testing.T) {
	app := newFixtureApplication(t)
	user, err := app.persistence.Users.Create(context.Background(), &auth.User{ID: uuid.New(), Username: "owner", Email: "owner@example.com", Role: auth.RoleOwner, Status: auth.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	cfg := app.config.authConfig()
	auther := auth.NewAuthenticator(auth.NewUserProvider(userTracker{users: app.persistence.Users}), cfg)
	issuer, err := principalTokenIssuer(auther.TokenService(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	token, err := issuer.GeneratePrincipal(auth.NewIdentityFromUser(user), map[string]any{"provider": "supabase", "assurance_level": "aal1"})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	app.config.Address = probe.Addr().String()
	_ = probe.Close()
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveUntilContext(ctx, app, 3*time.Second) }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("host did not stop")
		}
	})
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	base := "http://" + app.config.Address
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get(base + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, authenticated := range []bool{false, true} {
		req, err := http.NewRequest(http.MethodGet, base+"/admin/dashboard", nil)
		if err != nil {
			t.Fatal(err)
		}
		if authenticated {
			req.AddCookie(&http.Cookie{Name: cfg.GetContextKey(), Value: token})
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !authenticated {
			if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "/admin/login") {
				t.Errorf("unauthenticated status/location = %d %q", resp.StatusCode, resp.Header.Get("Location"))
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authenticated dashboard status=%d body=%.1200s", resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "Supabase") {
			t.Fatal("dashboard missing configured provider content")
		}
		if strings.Contains(string(body), "client-secret") || strings.Contains(string(body), token) {
			t.Fatal("dashboard leaked credentials")
		}
	}
}
