package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("Supabase dashboard stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadRuntimeConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app, err := buildApplication(ctx, cfg)
	if err != nil {
		return err
	}
	return serveUntilContext(ctx, app, 10*time.Second)
}

func serveUntilContext(ctx context.Context, app *application, shutdownTimeout time.Duration) error {
	served := make(chan error, 1)
	go func() { served <- app.Serve() }()
	var serveErr error
	stopped := false
	select {
	case <-ctx.Done():
	case serveErr = <-served:
		stopped = true
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	closeErr := app.Close(shutdownCtx)
	if !stopped {
		select {
		case serveErr = <-served:
		case <-shutdownCtx.Done():
			return errors.Join(closeErr, shutdownCtx.Err())
		}
	}
	if serveErr != nil && !errors.Is(serveErr, context.Canceled) {
		serveErr = fmt.Errorf("serve dashboard: %w", serveErr)
	} else {
		serveErr = nil
	}
	return errors.Join(serveErr, closeErr)
}
