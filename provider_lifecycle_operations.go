package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrLifecycleOperationUnavailable = errors.New("auth: lifecycle operation store unavailable")
	ErrLifecycleOperationConflict    = errors.New("auth: lifecycle operation revision conflict")
)

type LifecycleOperationPhase string

const (
	LifecyclePhasePending          LifecycleOperationPhase = "pending"
	LifecyclePhaseInFlight         LifecycleOperationPhase = "in_flight"
	LifecyclePhaseSucceeded        LifecycleOperationPhase = "succeeded"
	LifecyclePhaseFailed           LifecycleOperationPhase = "failed"
	LifecyclePhasePendingReconcile LifecycleOperationPhase = "pending_reconcile"
	LifecyclePhaseSkipped          LifecycleOperationPhase = "skipped"
)

type LifecycleOperationClaim struct {
	OperationID string
	Fingerprint string
	Action      ProviderOperationAction
}

type LifecycleOperationClaimDisposition string

const (
	LifecycleOperationClaimed  LifecycleOperationClaimDisposition = "claimed"
	LifecycleOperationExisting LifecycleOperationClaimDisposition = "existing"
)

type LifecycleOperationRecord struct {
	OperationID            string
	Fingerprint            string
	Action                 ProviderOperationAction
	LocalPhase             LifecycleOperationPhase
	RemotePhase            LifecycleOperationPhase
	FreshnessPhase         LifecycleOperationPhase
	Local                  ProviderOperationOutcome
	Remote                 ProviderOperationOutcome
	Freshness              ProviderOperationOutcome
	ProviderIdempotencyKey string
	RemoteAttempt          int
	RemoteLeaseOwner       string
	RemoteLeaseUntil       time.Time
	Revision               int64
	Completed              bool
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

func (r LifecycleOperationRecord) Validate() error {
	if strings.TrimSpace(r.OperationID) == "" || strings.TrimSpace(r.Fingerprint) == "" ||
		!r.Action.valid() || r.Revision <= 0 {
		return ErrProviderOperationInvalid
	}
	return nil
}

type LifecycleOperationPendingPolicy struct {
	Now        time.Time
	LeaseOwner string
	Lease      time.Duration
	Limit      int
}

type LifecycleOperationStore interface {
	Claim(
		context.Context,
		LifecycleOperationClaim,
	) (LifecycleOperationRecord, LifecycleOperationClaimDisposition, error)
	Load(context.Context, string) (LifecycleOperationRecord, error)
	Advance(context.Context, int64, LifecycleOperationRecord) (LifecycleOperationRecord, error)
	ClaimPending(context.Context, LifecycleOperationPendingPolicy) ([]LifecycleOperationRecord, error)
	Durable() bool
}

// InMemoryLifecycleOperationStore is an explicit development and compatibility
// store. It is process-local and must not be used when durable coordination is
// required.
type InMemoryLifecycleOperationStore struct {
	mu      sync.Mutex
	records map[string]LifecycleOperationRecord
	now     func() time.Time
}

func NewInMemoryLifecycleOperationStore(now func() time.Time) *InMemoryLifecycleOperationStore {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &InMemoryLifecycleOperationStore{
		records: make(map[string]LifecycleOperationRecord),
		now:     now,
	}
}

func (s *InMemoryLifecycleOperationStore) Durable() bool { return false }

func (s *InMemoryLifecycleOperationStore) Claim(
	_ context.Context,
	claim LifecycleOperationClaim,
) (LifecycleOperationRecord, LifecycleOperationClaimDisposition, error) {
	claim.OperationID = strings.TrimSpace(claim.OperationID)
	claim.Fingerprint = strings.TrimSpace(claim.Fingerprint)
	if claim.OperationID == "" || claim.Fingerprint == "" || !claim.Action.valid() {
		return LifecycleOperationRecord{}, "", ErrProviderOperationInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.records[claim.OperationID]; ok {
		if current.Fingerprint != claim.Fingerprint {
			return LifecycleOperationRecord{}, "", fmt.Errorf(
				"%w: operation ID reuse mismatch",
				ErrProviderOperationConflict,
			)
		}
		return current, LifecycleOperationExisting, nil
	}
	now := s.now().UTC()
	record := LifecycleOperationRecord{
		OperationID:            claim.OperationID,
		Fingerprint:            claim.Fingerprint,
		Action:                 claim.Action,
		LocalPhase:             LifecyclePhasePending,
		RemotePhase:            LifecyclePhasePending,
		FreshnessPhase:         LifecyclePhasePending,
		ProviderIdempotencyKey: claim.Fingerprint,
		Revision:               1,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	s.records[record.OperationID] = record
	return record, LifecycleOperationClaimed, nil
}

func (s *InMemoryLifecycleOperationStore) Load(
	_ context.Context,
	operationID string,
) (LifecycleOperationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[strings.TrimSpace(operationID)]
	if !ok {
		return LifecycleOperationRecord{}, ErrLifecycleOperationUnavailable
	}
	return record, nil
}

func (s *InMemoryLifecycleOperationStore) Advance(
	_ context.Context,
	expectedRevision int64,
	next LifecycleOperationRecord,
) (LifecycleOperationRecord, error) {
	if err := next.Validate(); err != nil {
		return LifecycleOperationRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[next.OperationID]
	if !ok {
		return LifecycleOperationRecord{}, ErrLifecycleOperationUnavailable
	}
	if current.Fingerprint != next.Fingerprint {
		return LifecycleOperationRecord{}, ErrProviderOperationConflict
	}
	if current.Revision != expectedRevision {
		return LifecycleOperationRecord{}, ErrLifecycleOperationConflict
	}
	next.Revision = current.Revision + 1
	next.CreatedAt = current.CreatedAt
	next.UpdatedAt = s.now().UTC()
	s.records[next.OperationID] = next
	return next, nil
}

func (s *InMemoryLifecycleOperationStore) ClaimPending(
	_ context.Context,
	policy LifecycleOperationPendingPolicy,
) ([]LifecycleOperationRecord, error) {
	if policy.Now.IsZero() {
		policy.Now = s.now().UTC()
	}
	if policy.Lease <= 0 {
		policy.Lease = 30 * time.Second
	}
	if policy.Limit <= 0 {
		policy.Limit = 100
	}
	if strings.TrimSpace(policy.LeaseOwner) == "" || policy.Limit > 10_000 {
		return nil, ErrProviderOperationInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LifecycleOperationRecord, 0, policy.Limit)
	for id, current := range s.records {
		if len(out) >= policy.Limit {
			break
		}
		pendingAvailable := current.RemotePhase == LifecyclePhasePendingReconcile &&
			(current.RemoteLeaseUntil.IsZero() ||
				!policy.Now.Before(current.RemoteLeaseUntil))
		inFlightExpired := current.RemotePhase == LifecyclePhaseInFlight &&
			!current.RemoteLeaseUntil.IsZero() &&
			!policy.Now.Before(current.RemoteLeaseUntil)
		if !pendingAvailable && !inFlightExpired {
			continue
		}
		current.RemotePhase = LifecyclePhasePendingReconcile
		current.RemoteLeaseOwner = policy.LeaseOwner
		current.RemoteLeaseUntil = policy.Now.Add(policy.Lease)
		current.Revision++
		current.UpdatedAt = policy.Now
		s.records[id] = current
		out = append(out, current)
	}
	return out, nil
}

var _ LifecycleOperationStore = (*InMemoryLifecycleOperationStore)(nil)
