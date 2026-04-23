package auth

import (
	"context"
	"strconv"
	"strings"
	"time"
)

const (
	TemporaryPasswordMetadataKey          = "password_temporary"
	PasswordChangeRequiredMetadataKey     = "password_change_required"
	TemporaryPasswordIssuedAtMetadataKey  = "password_temporary_issued_at"
	TemporaryPasswordExpiresAtMetadataKey = "password_temporary_expires_at"
)

type metadataAwareIdentity interface {
	Metadata() map[string]any
}

// TemporaryPasswordState is the normalized state carried in user metadata.
type TemporaryPasswordState struct {
	Temporary      bool
	ChangeRequired bool
	IssuedAt       time.Time
	ExpiresAt      time.Time
}

// TemporaryPasswordStateFromMetadata extracts temporary-password state from user metadata.
func TemporaryPasswordStateFromMetadata(metadata map[string]any) TemporaryPasswordState {
	if len(metadata) == 0 {
		return TemporaryPasswordState{}
	}
	return TemporaryPasswordState{
		Temporary:      metadataBool(metadata[TemporaryPasswordMetadataKey]),
		ChangeRequired: metadataBool(metadata[PasswordChangeRequiredMetadataKey]),
		IssuedAt:       metadataTime(metadata[TemporaryPasswordIssuedAtMetadataKey]),
		ExpiresAt:      metadataTime(metadata[TemporaryPasswordExpiresAtMetadataKey]),
	}
}

// Expired reports whether the temporary password is past its expiry at the provided time.
func (s TemporaryPasswordState) Expired(now time.Time) bool {
	if !s.Temporary || s.ExpiresAt.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	return !now.Before(s.ExpiresAt)
}

// TemporaryPasswordClaimsDecorator copies compact temporary-password hints into JWT metadata.
func TemporaryPasswordClaimsDecorator() ClaimsDecorator {
	return ClaimsDecoratorFunc(func(_ context.Context, identity Identity, claims *JWTClaims) error {
		if identity == nil || claims == nil {
			return nil
		}
		carrier, ok := identity.(metadataAwareIdentity)
		if !ok {
			return nil
		}
		state := TemporaryPasswordStateFromMetadata(carrier.Metadata())
		if !state.Temporary && !state.ChangeRequired {
			return nil
		}
		if claims.Metadata == nil {
			claims.Metadata = map[string]any{}
		}
		claims.Metadata[TemporaryPasswordMetadataKey] = state.Temporary
		claims.Metadata[PasswordChangeRequiredMetadataKey] = state.ChangeRequired || state.Temporary
		if !state.IssuedAt.IsZero() {
			claims.Metadata[TemporaryPasswordIssuedAtMetadataKey] = state.IssuedAt.Format(time.RFC3339Nano)
		}
		if !state.ExpiresAt.IsZero() {
			claims.Metadata[TemporaryPasswordExpiresAtMetadataKey] = state.ExpiresAt.Format(time.RFC3339Nano)
		}
		return nil
	})
}

func metadataBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(v))
		return err == nil && parsed
	default:
		return false
	}
}

func metadataTime(value any) time.Time {
	switch v := value.(type) {
	case time.Time:
		return v
	case *time.Time:
		if v == nil {
			return time.Time{}
		}
		return *v
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return time.Time{}
		}
		if parsed, err := time.Parse(time.RFC3339Nano, trimmed); err == nil {
			return parsed
		}
		if parsed, err := time.Parse(time.RFC3339, trimmed); err == nil {
			return parsed
		}
		return time.Time{}
	default:
		return time.Time{}
	}
}
