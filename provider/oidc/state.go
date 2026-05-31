package oidc

import (
	"context"
	"sync"
	"time"
)

type MemoryStateStore struct {
	mu     sync.Mutex
	clock  func() time.Time
	states map[string]StateRecord
}

func NewMemoryStateStore(clock func() time.Time) *MemoryStateStore {
	if clock == nil {
		clock = time.Now
	}
	return &MemoryStateStore{clock: clock, states: map[string]StateRecord{}}
}

func (s *MemoryStateStore) Save(_ context.Context, state StateRecord) error {
	if s == nil {
		return ErrInvalidState
	}
	if state.State == "" {
		return ErrInvalidState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.State] = state
	return nil
}

func (s *MemoryStateStore) Consume(_ context.Context, state string) (StateRecord, error) {
	if s == nil {
		return StateRecord{}, ErrInvalidState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.states[state]
	if !ok {
		return StateRecord{}, ErrInvalidState
	}
	delete(s.states, state)
	if !record.ExpiresAt.IsZero() && !s.clock().Before(record.ExpiresAt) {
		return StateRecord{}, cloneWithProvider(ErrInvalidState, record.ProviderKey, map[string]any{"cause": "state expired"})
	}
	return record, nil
}
