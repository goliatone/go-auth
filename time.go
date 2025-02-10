package auth

import "time"

// IsWithinThresholdPeriod checks if the given time is within the threshold
func IsWithinThresholdPeriod(t time.Time, pattern string) (bool, error) {
	duration, err := time.ParseDuration(pattern)
	if err != nil {
		return false, err
	}

	threshold := time.Now().Add(-duration)
	if t.After(threshold) {
		return true, nil
	}

	return false, nil
}

// IsOutsideThresholdPeriod is the negation of IsWithinThresholdPeriod
func IsOutsideThresholdPeriod(t time.Time, pattern string) (bool, error) {
	valid, err := IsWithinThresholdPeriod(t, pattern)
	if err != nil {
		return false, err
	}

	return !valid, nil
}
