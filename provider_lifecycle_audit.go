package auth

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

const providerAuditFingerprintPrefix = "sha256:"

// ProviderAuditFingerprint is a one-way correlation value safe for activity
// payloads. It preserves equality without retaining the source string.
type ProviderAuditFingerprint string

// FingerprintProviderAuditValue removes raw free-form values from provider
// lifecycle audit data. Values are always transformed; callers must retain the
// ProviderAuditFingerprint type instead of round-tripping it through string.
func FingerprintProviderAuditValue(value string) ProviderAuditFingerprint {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return ProviderAuditFingerprint(fmt.Sprintf("%s%x", providerAuditFingerprintPrefix, sum))
}

// NewProviderLifecycleActivityEvent constructs a secret-free audit event from
// typed lifecycle inputs. Security-state delivery remains the coordinator's
// responsibility; this event is best-effort audit context only.
func NewProviderLifecycleActivityEvent(
	operation AuthorizedOperationContext,
	outcome ProviderOperationOutcome,
	occurredAt time.Time,
) (ActivityEvent, error) {
	if err := operation.Validate(operation.Action, operation.Environment, operation.Target.Provider); err != nil {
		return ActivityEvent{}, err
	}
	if err := outcome.Validate(); err != nil {
		return ActivityEvent{}, err
	}
	eventType, ok := providerLifecycleEventType(operation.Action)
	if !ok {
		return ActivityEvent{}, fmt.Errorf("%w: action has no audit event", ErrProviderOperationInvalid)
	}
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	return ActivityEvent{
		EventType: eventType,
		Actor: ActorRef{
			ID:   string(FingerprintProviderAuditValue(operation.Actor.ID)),
			Type: string(FingerprintProviderAuditValue(operation.Actor.Type)),
		},
		UserID: string(FingerprintProviderAuditValue(operation.Target.ApplicationSubject)),
		Metadata: map[string]any{
			"operation_id":        FingerprintProviderAuditValue(operation.OperationID),
			"action":              operation.Action,
			"result":              outcome.Status,
			"reason":              FingerprintProviderAuditValue(operation.Reason),
			"request_id":          FingerprintProviderAuditValue(operation.RequestID),
			"provider_request_id": FingerprintProviderAuditValue(outcome.ProviderRequestID),
			"provider_session_id": FingerprintProviderAuditValue(operation.ProviderSessionID),
			"environment":         FingerprintProviderAuditValue(operation.Environment),
			"target_provider":     FingerprintProviderAuditValue(operation.Target.Provider),
			"target_subject":      FingerprintProviderAuditValue(operation.Target.Subject),
			"target_object":       FingerprintProviderAuditValue(operation.Target.ObjectID),
			"session_effect":      outcome.ProviderSessionEffect,
			"retryable":           outcome.Retryable,
			"residual_expires_at": outcome.ResidualAccessExpires,
		},
		OccurredAt: occurredAt,
	}, nil
}

func providerLifecycleEventType(action ProviderOperationAction) (ActivityEventType, bool) {
	switch action {
	case ProviderActionInvite:
		return ActivityEventProviderInvite, true
	case ProviderActionStartRecovery:
		return ActivityEventProviderRecovery, true
	case ProviderActionSuspend:
		return ActivityEventProviderAccountSuspend, true
	case ProviderActionActivate:
		return ActivityEventProviderAccountActivate, true
	case ProviderActionGetAccountState:
		return ActivityEventProviderAccountState, true
	case ProviderActionListFactors:
		return ActivityEventProviderFactorList, true
	case ProviderActionRemoveFactor:
		return ActivityEventProviderFactorRemove, true
	case ProviderActionAuthorizationDetails:
		return ActivityEventProviderAuthDetails, true
	case ProviderActionAuthorizationApprove:
		return ActivityEventProviderAuthApprove, true
	case ProviderActionAuthorizationDeny:
		return ActivityEventProviderAuthDeny, true
	default:
		return "", false
	}
}

func IsProviderLifecycleActivity(eventType ActivityEventType) bool {
	switch eventType {
	case ActivityEventProviderInvite,
		ActivityEventProviderRecovery,
		ActivityEventProviderAccountSuspend,
		ActivityEventProviderAccountActivate,
		ActivityEventProviderAccountState,
		ActivityEventProviderFactorList,
		ActivityEventProviderFactorRemove,
		ActivityEventProviderAuthDetails,
		ActivityEventProviderAuthApprove,
		ActivityEventProviderAuthDeny:
		return true
	default:
		return false
	}
}
