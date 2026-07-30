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
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if closeErr := app.Close(shutdownCtx); closeErr != nil {
			slog.Error("Supabase dashboard shutdown failed", "error", closeErr)
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.Serve()
	}()
	select {
	case <-ctx.Done():
		return nil
	case serveErr := <-errCh:
		if serveErr == nil || errors.Is(serveErr, context.Canceled) {
			return nil
		}
		return fmt.Errorf("serve dashboard: %w", serveErr)
	}
}
