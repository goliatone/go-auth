package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestHostSIGTERM(t *testing.T) {
	if address := os.Getenv("AUTH_TEST_SIGNAL_ADDRESS"); address != "" {
		runSignalFixture(t, address)
		return
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	_ = probe.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHostSIGTERM$", "-test.count=1")
	cmd.Env = append(os.Environ(), "AUTH_TEST_SIGNAL_ADDRESS="+address)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	exited := make(chan struct{})
	go func() { done <- cmd.Wait(); close(exited) }()
	t.Cleanup(func() { cancel(); <-exited })
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := client.Get("http://" + address + "/login")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case err := <-done:
			t.Fatalf("host exited before readiness: %v %s", err, output.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("host did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("signal shutdown: %v %s", err, output.String())
		}
	case <-time.After(7 * time.Second):
		t.Fatal("signal shutdown was not bounded")
	}
}

func runSignalFixture(t *testing.T, address string) {
	app := newHTTPServerTestApp(t)
	if err := serveUntilSignal(app.srv, address); err != nil {
		t.Fatal(err)
	}
}
