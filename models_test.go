package auth

import (
	"testing"
)

func TestUserEnsureStatusDefaultsToActive(t *testing.T) {
	u := &User{}

	u.EnsureStatus()

	if u.Status != UserStatusActive {
		t.Fatalf("expected default status %q, got %q", UserStatusActive, u.Status)
	}
}

func TestUserStatusHelpers(t *testing.T) {
	cases := []struct {
		name         string
		status       UserStatus
		check        func(*User) bool
		expectResult bool
	}{
		{
			name:         "active",
			status:       UserStatusActive,
			check:        (*User).IsActive,
			expectResult: true,
		},
		{
			name:         "pending",
			status:       UserStatusPending,
			check:        (*User).IsPending,
			expectResult: true,
		},
		{
			name:         "suspended",
			status:       UserStatusSuspended,
			check:        (*User).IsSuspended,
			expectResult: true,
		},
		{
			name:         "disabled",
			status:       UserStatusDisabled,
			check:        (*User).IsDisabled,
			expectResult: true,
		},
		{
			name:         "archived",
			status:       UserStatusArchived,
			check:        (*User).IsArchived,
			expectResult: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user := &User{Status: tc.status}
			if got := tc.check(user); got != tc.expectResult {
				t.Fatalf("helper returned %t for status %q, expected %t", got, tc.status, tc.expectResult)
			}
		})
	}
}
