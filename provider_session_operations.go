package auth

import (
	"fmt"
	"strings"
	"time"
)

// ProviderSessionOperationsConfig is the production enablement gate. Values
// are intentionally supplied by the host/deployment rather than guessed by
// this library.
type ProviderSessionOperationsConfig struct {
	Environment              string
	PostgresOwner            string
	EncryptionKeySource      string
	KeyRotationOwner         string
	ActiveKeyPolicy          string
	RetiredKeyPolicy         string
	CookiePolicyOwner        string
	IdleLifetime             time.Duration
	MaxLifetime              time.Duration
	StateRetention           time.Duration
	SessionRetention         time.Duration
	TokenRetention           time.Duration
	CleanupSchedule          string
	CleanupOwner             string
	MonitoringOwner          string
	OutagePolicy             string
	EmergencyRevocationOwner string
	EmergencyProcedure       string
}

func (c ProviderSessionOperationsConfig) Validate(binding ProviderSessionBinding, idle, maximum time.Duration) error {
	required := map[string]string{
		"environment":                c.Environment,
		"postgres_owner":             c.PostgresOwner,
		"encryption_key_source":      c.EncryptionKeySource,
		"key_rotation_owner":         c.KeyRotationOwner,
		"active_key_policy":          c.ActiveKeyPolicy,
		"retired_key_policy":         c.RetiredKeyPolicy,
		"cookie_policy_owner":        c.CookiePolicyOwner,
		"cleanup_schedule":           c.CleanupSchedule,
		"cleanup_owner":              c.CleanupOwner,
		"monitoring_owner":           c.MonitoringOwner,
		"outage_policy":              c.OutagePolicy,
		"emergency_revocation_owner": c.EmergencyRevocationOwner,
		"emergency_procedure":        c.EmergencyProcedure,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: production operations field %s is required", ErrProviderSessionInvalid, field)
		}
	}
	if !strings.EqualFold(strings.TrimSpace(c.Environment), strings.TrimSpace(binding.Environment)) {
		return fmt.Errorf("%w: operations environment does not match session binding", ErrProviderSessionBinding)
	}
	if c.IdleLifetime <= 0 || c.MaxLifetime <= 0 || c.IdleLifetime > c.MaxLifetime ||
		c.IdleLifetime != idle || c.MaxLifetime != maximum {
		return fmt.Errorf("%w: operations session lifetimes do not match runtime", ErrProviderSessionInvalid)
	}
	if c.StateRetention <= 0 || c.SessionRetention <= 0 || c.TokenRetention <= 0 ||
		c.TokenRetention > c.SessionRetention {
		return fmt.Errorf("%w: invalid production retention policy", ErrProviderSessionInvalid)
	}
	return nil
}
