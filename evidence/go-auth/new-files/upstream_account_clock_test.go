package auth

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestUpstreamAccountObservationEvaluationTime(t *testing.T) {
	for _, privileged := range []bool{false, true} {
		for _, tc := range []struct {
			name    string
			offset  time.Duration
			wantErr bool
		}{
			{"live", 0, false}, {"future", time.Nanosecond, true}, {"stale", -2 * time.Minute, true}, {"boundary", -time.Minute, false},
		} {
			t.Run(tc.name+map[bool]string{false: "/normal", true: "/privileged"}[privileged], func(t *testing.T) {
				now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
				calls := 0
				r, err := NewCompositeAccountStateResolver(CompositeAccountStateResolverConfig{
					Now: func() time.Time { return now }, CacheTTL: time.Minute,
					Sources: []NamedAccountStateSource{{Name: "source-a", Source: AccountStateSourceFunc(func(context.Context, AuthenticatedPrincipal) (AccountStateObservation, error) {
						calls++
						now = now.Add(time.Second)
						return AccountStateObservation{State: AccountStateActive, ObservedAt: now.Add(tc.offset)}, nil
					})}},
				})
				require.NoError(t, err)
				req := AccountStateRequest{Principal: accountStatePrincipal(t), MaximumStaleness: time.Minute, Privileged: privileged}
				result, err := r.ResolveCurrentAccountState(context.Background(), req)
				if tc.wantErr {
					require.ErrorIs(t, err, ErrAccountStateUnavailable)
					require.True(t, result.InvalidEvidence)
					_, err = r.ResolveCurrentAccountState(context.Background(), req)
					require.ErrorIs(t, err, ErrAccountStateUnavailable)
					require.Equal(t, 2, calls, "invalid evidence was cached")
				} else {
					require.NoError(t, err)
					require.Equal(t, AccountStateActive, result.State)
				}
			})
		}
	}
}

func TestUpstreamAccountObservationAgesWhileReadingOtherSources(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r, err := NewCompositeAccountStateResolver(CompositeAccountStateResolverConfig{
		Now: func() time.Time { return now }, CacheTTL: time.Minute,
		Sources: []NamedAccountStateSource{
			{Name: "source-a", Source: AccountStateSourceFunc(func(context.Context, AuthenticatedPrincipal) (AccountStateObservation, error) {
				return AccountStateObservation{State: AccountStateActive, ObservedAt: now}, nil
			})},
			{Name: "source-b", Source: AccountStateSourceFunc(func(context.Context, AuthenticatedPrincipal) (AccountStateObservation, error) {
				now = now.Add(2 * time.Minute)
				return AccountStateObservation{State: AccountStateActive, ObservedAt: now}, nil
			})},
		},
	})
	require.NoError(t, err)
	result, err := r.ResolveCurrentAccountState(context.Background(), AccountStateRequest{Principal: accountStatePrincipal(t), MaximumStaleness: time.Minute, Privileged: true})
	require.ErrorIs(t, err, ErrAccountStateUnavailable)
	require.True(t, result.InvalidEvidence)
}

func TestUpstreamAccountObservationCacheStartsAfterRead(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	calls := 0
	r, err := NewCompositeAccountStateResolver(CompositeAccountStateResolverConfig{
		Now: func() time.Time { return now }, CacheTTL: time.Minute,
		Sources: []NamedAccountStateSource{{Name: "live", Source: AccountStateSourceFunc(func(context.Context, AuthenticatedPrincipal) (AccountStateObservation, error) {
			calls++
			now = now.Add(2 * time.Minute)
			return AccountStateObservation{State: AccountStateActive}, nil
		})}},
	})
	require.NoError(t, err)
	req := AccountStateRequest{Principal: accountStatePrincipal(t), MaximumStaleness: time.Minute, Privileged: true}
	result, err := r.ResolveCurrentAccountState(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, now, result.ObservedAt)
	result, err = r.ResolveCurrentAccountState(context.Background(), req)
	require.NoError(t, err)
	require.True(t, result.FromCache)
	require.Equal(t, 1, calls)
	now = now.Add(time.Minute)
	result, err = r.ResolveCurrentAccountState(context.Background(), req)
	require.NoError(t, err)
	require.False(t, result.FromCache)
	require.Equal(t, 2, calls)
}
