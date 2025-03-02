package auth_test

import (
	"testing"
	"time"

	"github.com/goliatone/go-auth"
	"github.com/stretchr/testify/assert"
)

func TestIsWithinThresholdPeriod(t *testing.T) {
	tests := []struct {
		name          string
		inputTime     time.Time
		thresholdExpr string
		expected      bool
		expectErr     bool
	}{
		{
			name:          "Within 1 hour threshold",
			inputTime:     time.Now().Add(-30 * time.Minute),
			thresholdExpr: "1h",
			expected:      true,
			expectErr:     false,
		},
		{
			name:          "Outside 1 hour threshold",
			inputTime:     time.Now().Add(-90 * time.Minute),
			thresholdExpr: "1h",
			expected:      false,
			expectErr:     false,
		},
		{
			name:          "At exact threshold",
			inputTime:     time.Now().Add(-1 * time.Hour),
			thresholdExpr: "1h",
			expected:      false, // we check if time is AFTER threshold
			expectErr:     false,
		},
		{
			name:          "Complex threshold (2h30m)",
			inputTime:     time.Now().Add(-2 * time.Hour),
			thresholdExpr: "2h30m",
			expected:      true,
			expectErr:     false,
		},
		{
			name:          "Future time",
			inputTime:     time.Now().Add(1 * time.Hour),
			thresholdExpr: "2h",
			expected:      true,
			expectErr:     false,
		},
		{
			name:          "Invalid threshold expression",
			inputTime:     time.Now(),
			thresholdExpr: "invalid",
			expected:      false,
			expectErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := auth.IsWithinThresholdPeriod(tt.inputTime, tt.thresholdExpr)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestIsOutsideThresholdPeriod(t *testing.T) {
	tests := []struct {
		name          string
		inputTime     time.Time
		thresholdExpr string
		expected      bool
		expectErr     bool
	}{
		{
			name:          "Within 1 hour threshold",
			inputTime:     time.Now().Add(-30 * time.Minute),
			thresholdExpr: "1h",
			expected:      false,
			expectErr:     false,
		},
		{
			name:          "Outside 1 hour threshold",
			inputTime:     time.Now().Add(-90 * time.Minute),
			thresholdExpr: "1h",
			expected:      true,
			expectErr:     false,
		},
		{
			name:          "Invalid threshold expression",
			inputTime:     time.Now(),
			thresholdExpr: "invalid",
			expected:      false,
			expectErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := auth.IsOutsideThresholdPeriod(tt.inputTime, tt.thresholdExpr)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestThresholdFunctionsComplementary(t *testing.T) {
	// IsWithinThresholdPeriod and IsOutsideThresholdPeriod should return opposite values

	testTimes := []time.Time{
		time.Now(),
		time.Now().Add(-30 * time.Minute),
		time.Now().Add(-2 * time.Hour),
		time.Now().Add(1 * time.Hour),
	}

	thresholds := []string{
		"1h",
		"24h",
		"15m",
		"2h30m",
	}

	for _, inputTime := range testTimes {
		for _, threshold := range thresholds {
			within, err1 := auth.IsWithinThresholdPeriod(inputTime, threshold)
			outside, err2 := auth.IsOutsideThresholdPeriod(inputTime, threshold)

			assert.NoError(t, err1)
			assert.NoError(t, err2)

			assert.NotEqual(t, within, outside, "IsWithinThresholdPeriod and IsOutsideThresholdPeriod should be complementary")
		}
	}
}
