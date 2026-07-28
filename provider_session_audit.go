package auth

import (
	"fmt"
	"strings"
	"time"
)

type ProviderSessionReasonCode string

const (
	ProviderSessionReasonLogout               ProviderSessionReasonCode = "logout"
	ProviderSessionReasonAccountSuspended     ProviderSessionReasonCode = "account_suspended"
	ProviderSessionReasonFactorChanged        ProviderSessionReasonCode = "factor_changed"
	ProviderSessionReasonAuthorizationChange  ProviderSessionReasonCode = "authorization_changed"
	ProviderSessionReasonAdministrativeRevoke ProviderSessionReasonCode = "administrative_revoke"
	ProviderSessionReasonExpired              ProviderSessionReasonCode = "expired"
	ProviderSessionReasonRefreshUncertain     ProviderSessionReasonCode = "refresh_uncertain"
	ProviderSessionReasonLegacyExternal       ProviderSessionReasonCode = "legacy_external"
)

func (c ProviderSessionReasonCode) Valid() bool {
	switch c {
	case ProviderSessionReasonLogout,
		ProviderSessionReasonAccountSuspended,
		ProviderSessionReasonFactorChanged,
		ProviderSessionReasonAuthorizationChange,
		ProviderSessionReasonAdministrativeRevoke,
		ProviderSessionReasonExpired,
		ProviderSessionReasonRefreshUncertain,
		ProviderSessionReasonLegacyExternal:
		return true
	default:
		return false
	}
}

type ProviderSessionReason struct {
	Code              ProviderSessionReasonCode
	DetailFingerprint ProviderAuditFingerprint
}

func NewProviderSessionReason(
	code ProviderSessionReasonCode,
	detail string,
) (ProviderSessionReason, error) {
	if !code.Valid() {
		return ProviderSessionReason{}, ErrProviderSessionInvalid
	}
	return ProviderSessionReason{
		Code:              code,
		DetailFingerprint: FingerprintProviderAuditValue(detail),
	}, nil
}

func ProviderSessionReasonFromLegacy(detail string) ProviderSessionReason {
	normalized := strings.ToLower(strings.TrimSpace(detail))
	code := ProviderSessionReasonLegacyExternal
	switch normalized {
	case "logout", "user logout", "duplicate logout":
		code = ProviderSessionReasonLogout
	case "suspend", "suspended", "account suspended":
		code = ProviderSessionReasonAccountSuspended
	case "factor removed", "verified factor removed", "factor changed":
		code = ProviderSessionReasonFactorChanged
	case "permission changed", "authorization state changed":
		code = ProviderSessionReasonAuthorizationChange
	case "administrative revoke", "admin revoke":
		code = ProviderSessionReasonAdministrativeRevoke
	case "expired", "refresh token unavailable", "provider rejected refresh":
		code = ProviderSessionReasonExpired
	case "ambiguous provider refresh", "refresh reconciliation unavailable",
		"invalid refresh result", "empty reconciled token set",
		"unknown reconciliation result", "token envelope unavailable",
		"encode refresh result failed", "seal refresh result failed":
		code = ProviderSessionReasonRefreshUncertain
	}
	return ProviderSessionReason{
		Code:              code,
		DetailFingerprint: FingerprintProviderAuditValue(detail),
	}
}

func EncodeProviderSessionReason(reason ProviderSessionReason) string {
	if !reason.Code.Valid() {
		reason.Code = ProviderSessionReasonLegacyExternal
	}
	fingerprint := EnsureProviderAuditFingerprint(string(reason.DetailFingerprint))
	return string(reason.Code) + "|" + string(fingerprint)
}

func ParseProviderSessionReason(value string) ProviderSessionReason {
	parts := strings.SplitN(strings.TrimSpace(value), "|", 2)
	if len(parts) == 2 {
		code := ProviderSessionReasonCode(parts[0])
		rawFingerprint := strings.TrimSpace(parts[1])
		fingerprint := EnsureProviderAuditFingerprint(rawFingerprint)
		if code.Valid() && fingerprint != "" {
			return ProviderSessionReason{Code: code, DetailFingerprint: fingerprint}
		}
	}
	return ProviderSessionReasonFromLegacy(value)
}

type ProviderSessionActivityMetadata struct {
	Result              string
	Reason              ProviderSessionReason
	RemoteStatus        ProviderRemoteRevocationStatus
	RemoteRetryable     bool
	LocalOnly           bool
	Target              string
	LifecycleGeneration int64
}

func NewProviderSessionActivityEvent(
	eventType ActivityEventType,
	session ProviderSession,
	metadata ProviderSessionActivityMetadata,
	occurredAt time.Time,
) (ActivityEvent, error) {
	if !IsProviderSessionActivity(eventType) {
		return ActivityEvent{}, fmt.Errorf("%w: unsupported provider-session event", ErrProviderSessionInvalid)
	}
	if strings.TrimSpace(session.LocalSessionID) == "" {
		return ActivityEvent{}, ErrProviderSessionInvalid
	}
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	safe := map[string]any{
		"local_session_id": EnsureProviderAuditFingerprint(session.LocalSessionID),
		"provider":         EnsureProviderAuditFingerprint(session.Binding.Provider),
		"application_id":   EnsureProviderAuditFingerprint(session.Binding.ApplicationID),
		"environment":      EnsureProviderAuditFingerprint(session.Binding.Environment),
		"status":           session.Status,
		"token_revision":   session.TokenRevision,
	}
	if metadata.Result != "" {
		switch metadata.Result {
		case "succeeded", "failed", "reauthentication_required":
			safe["result"] = metadata.Result
		default:
			return ActivityEvent{}, ErrProviderSessionInvalid
		}
	}
	if metadata.Reason.Code.Valid() {
		safe["reason_code"] = metadata.Reason.Code
		if metadata.Reason.DetailFingerprint != "" {
			safe["reason_fingerprint"] = EnsureProviderAuditFingerprint(
				string(metadata.Reason.DetailFingerprint),
			)
		}
	}
	if metadata.RemoteStatus != "" {
		safe["remote_status"] = metadata.RemoteStatus
		safe["remote_retryable"] = metadata.RemoteRetryable
	}
	if metadata.LocalOnly {
		safe["local_only"] = true
	}
	if metadata.Target != "" {
		safe["target"] = EnsureProviderAuditFingerprint(metadata.Target)
	}
	if metadata.LifecycleGeneration > 0 {
		safe["lifecycle_generation"] = metadata.LifecycleGeneration
	}
	return ActivityEvent{
		EventType:  eventType,
		UserID:     string(EnsureProviderAuditFingerprint(session.Principal.ApplicationSubject)),
		Metadata:   safe,
		OccurredAt: occurredAt,
	}, nil
}

func IsProviderSessionActivity(eventType ActivityEventType) bool {
	switch eventType {
	case ActivityEventProviderSessionCreated,
		ActivityEventProviderSessionRefreshed,
		ActivityEventProviderSessionUncertain,
		ActivityEventProviderSessionRevoked,
		ActivityEventProviderTokenAccessed:
		return true
	default:
		return false
	}
}
