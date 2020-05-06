package cmd

import "time"

//  timeInfo stores a timestamp
type timeInfo struct {
	timestamp time.Time
}

// setTimestamp sets the timestamp
func (t *timeInfo) setTimestamp(timestamp time.Time) {
	t.timestamp = timestamp
}

// getAge gets seconds since timestamp
func (t *timeInfo) getAge() float64 {
	if t.timestamp == (time.Time{}) {
		return -1
	}
	return time.Since(t.timestamp).Seconds()
}
