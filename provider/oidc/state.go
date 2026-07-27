package oidc

import (
	"context"
	"sync"
	"time"
)

type MemoryStateStore struct {
	mu        sync.Mutex
	clock     func() time.Time
	capacity  int
	states    map[string]StateRecord
	lastSweep time.Time
	hasSwept  bool
}

func NewMemoryStateStore(clock func() time.Time) *MemoryStateStore {
	return NewMemoryStateStoreWithCapacity(clock, DefaultStateCapacity)
}

func NewMemoryStateStoreWithCapacity(clock func() time.Time, capacity int) *MemoryStateStore {
	if clock == nil {
		clock = time.Now
	}
	if capacity <= 0 {
		capacity = DefaultStateCapacity
	}
	return &MemoryStateStore{clock: clock, capacity: capacity, states: map[string]StateRecord{}}
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
	now := s.clock()
	if !s.hasSwept || now.Sub(s.lastSweep) >= time.Second {
		for key, record := range s.states {
			if !record.ExpiresAt.IsZero() && !now.Before(record.ExpiresAt) {
				delete(s.states, key)
			}
		}
		s.lastSweep = now
		s.hasSwept = true
	}
	if _, exists := s.states[state.State]; exists {
		return cloneWithProvider(ErrInvalidState, state.ProviderKey, map[string]any{
			"cause": "duplicate state",
		})
	}
	if len(s.states) >= s.capacity {
		return cloneWithProvider(ErrInvalidState, state.ProviderKey, map[string]any{
			"cause": "state store capacity reached",
		})
	}
	if state.CreatedAt.IsZero() {
		state.CreatedAt = now
	}
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
