package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/goliatone/go-router"
)

// Exercise the actual host coordinator and native listener, including failures
// that Fiber's in-memory request helper cannot observe.
func TestHostLifecycle(t *testing.T) {
	t.Run("occupied address", func(t *testing.T) {
		occupied, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer occupied.Close()
		_, run, _, _ := lifecycleHost(t, occupied.Addr().String())
		done := make(chan error, 1)
		go func() { done <- run(context.Background(), time.Second) }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "address already in use") {
				t.Fatalf("startup error = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("startup failure did not reach coordinator")
		}
	})
	for _, expires := range []bool{false, true} {
		name := "ordinary request drains"
		if expires {
			name = "deadline is bounded and retryable"
		}
		t.Run(name, func(t *testing.T) {
			probe, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := probe.Addr().String()
			_ = probe.Close()
			routes, run, shutdown, healthy := lifecycleHost(t, address)
			entered, release := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			routes.Get("/__lifecycle/ready", func(c router.Context) error { return c.SendString("ready") })
			routes.Get("/__lifecycle/slow", func(c router.Context) error {
				close(entered)
				<-release
				if err := healthy(); err != nil {
					return err
				}
				return c.SendString("drained")
			})
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			timeout := 3 * time.Second
			if expires {
				timeout = 150 * time.Millisecond
			}
			done := make(chan error, 1)
			go func() { done <- run(ctx, timeout) }()
			client := &http.Client{Timeout: 5 * time.Second}
			defer client.CloseIdleConnections()
			deadline := time.Now().Add(5 * time.Second)
			for {
				resp, err := client.Get("http://" + address + "/__lifecycle/ready")
				if err == nil {
					// Drain the readiness response so the client reuses this connection.
					_, readErr := io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					if readErr != nil {
						t.Fatal(readErr)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("listener did not become ready", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			response := make(chan error, 1)
			go func() {
				resp, err := client.Get("http://" + address + "/__lifecycle/slow")
				if err != nil {
					response <- err
					return
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err == nil && (resp.StatusCode != http.StatusOK || string(body) != "drained") {
					err = fmt.Errorf("response %d %q", resp.StatusCode, body)
				}
				response <- err
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not enter")
			}
			stop()
			if expires {
				select {
				case err := <-done:
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("deadline error = %v", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("shutdown exceeded deadline bound")
				}
				if err := healthy(); err != nil {
					t.Errorf("active request resources closed before drain: %v", err)
				}
			} else {
				select {
				case err := <-done:
					t.Fatalf("shutdown returned before request drained: %v", err)
				case <-time.After(75 * time.Millisecond):
				}
			}
			close(release)
			select {
			case err := <-response:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("request did not complete")
			}
			if !expires {
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("shutdown did not complete")
				}
			} else {
				retryCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := shutdown(retryCtx); err != nil {
					t.Fatal("shutdown retry", err)
				}
			}
		})
	}
}

func lifecycleHost(t *testing.T, address string) (router.Router[*fiber.App], func(context.Context, time.Duration) error, func(context.Context) error, func() error) {
	app := newHTTPServerTestApp(t)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = app.srv.Shutdown(ctx)
	})
	return app.srv.Router(), func(ctx context.Context, timeout time.Duration) error {
		return serveUntilContext(ctx, app.srv, address, timeout)
	}, app.srv.Shutdown, func() error { return nil }
}
