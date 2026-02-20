package auth

import (
	"context"
	"testing"
)

func TestValidateResolverConfigured(t *testing.T) {
	err := ValidateResolverConfigured(true, nil)
	if err == nil {
		t.Fatalf("expected strict validation error when resolver is nil")
	}
	if err != ErrPermissionResolverRequired {
		t.Fatalf("expected ErrPermissionResolverRequired, got %v", err)
	}

	err = ValidateResolverConfigured(false, nil)
	if err != nil {
		t.Fatalf("expected nil error when strict mode disabled, got %v", err)
	}

	err = ValidateResolverConfigured(true, func(context.Context) ([]string, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("expected nil error when resolver is provided, got %v", err)
	}
}

func TestMustValidateResolverConfiguredPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic for strict mode nil resolver")
		}
	}()
	MustValidateResolverConfigured(true, nil)
}
