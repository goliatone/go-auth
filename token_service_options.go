package auth

import "strings"

const (
	// DefaultTokenWarnThresholdBytes emits a warning log when a signed JWT reaches
	// this size. It remains valid unless the hard limit is exceeded.
	DefaultTokenWarnThresholdBytes = 2048
	// DefaultTokenHardLimitBytes rejects tokens larger than this size to reduce
	// oversized cookie risk in downstream applications.
	DefaultTokenHardLimitBytes = 4096
)

const (
	// TokenTypeSession labels regular auth/session JWTs.
	TokenTypeSession = "session"
	// TokenTypeScoped labels short-lived scoped JWTs minted by MintScopedToken.
	TokenTypeScoped = "scoped"
	// TokenTypeCustom labels direct TokenService.SignClaims calls.
	TokenTypeCustom = "custom"
)

var defaultFatClaimsMetadataKeys = []string{
	"permissions",
	"permission_list",
	"permissions_list",
	"scopes",
	"scope_list",
	"scopes_list",
}

type tokenSizeGuardrails struct {
	warnThresholdBytes int
	hardLimitBytes     int
}

// TokenServiceOption customizes TokenService behavior without changing the
// TokenService interface.
type TokenServiceOption func(*TokenServiceImpl)

// WithLegacyFatClaims preserves legacy fat-claims behavior by disabling
// metadata minimization.
func WithLegacyFatClaims(enabled bool) TokenServiceOption {
	return func(ts *TokenServiceImpl) {
		if ts == nil {
			return
		}
		ts.legacyFatClaims = enabled
	}
}

// WithTokenSizeGuardrails overrides warning and hard-limit thresholds for signed JWT size.
// Values <= 0 disable the respective threshold.
func WithTokenSizeGuardrails(warnThresholdBytes, hardLimitBytes int) TokenServiceOption {
	return func(ts *TokenServiceImpl) {
		if ts == nil {
			return
		}
		guardrails := normalizeTokenSizeGuardrails(warnThresholdBytes, hardLimitBytes)
		ts.warnThresholdBytes = guardrails.warnThresholdBytes
		ts.hardLimitBytes = guardrails.hardLimitBytes
	}
}

// WithClaimsMetadataStripKeys overrides the metadata keys that are removed by
// default minimization. Matching is case-insensitive and normalizes "-" to "_".
func WithClaimsMetadataStripKeys(keys ...string) TokenServiceOption {
	return func(ts *TokenServiceImpl) {
		if ts == nil {
			return
		}
		ts.metadataStripKeys = makeClaimsMetadataStripSet(keys)
	}
}

func normalizeTokenSizeGuardrails(warnThresholdBytes, hardLimitBytes int) tokenSizeGuardrails {
	if warnThresholdBytes < 0 {
		warnThresholdBytes = 0
	}
	if hardLimitBytes < 0 {
		hardLimitBytes = 0
	}
	if hardLimitBytes > 0 && warnThresholdBytes >= hardLimitBytes {
		warnThresholdBytes = hardLimitBytes - 1
	}
	if warnThresholdBytes < 0 {
		warnThresholdBytes = 0
	}
	return tokenSizeGuardrails{
		warnThresholdBytes: warnThresholdBytes,
		hardLimitBytes:     hardLimitBytes,
	}
}

func normalizeClaimsMetadataKey(key string) string {
	key = strings.TrimSpace(strings.ToLower(key))
	key = strings.ReplaceAll(key, "-", "_")
	return key
}

func makeClaimsMetadataStripSet(keys []string) map[string]struct{} {
	set := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		normalized := normalizeClaimsMetadataKey(key)
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
	return set
}
