package cmd

import "time"

//  TimeInfo stores a timestamp
type TimeInfo struct {
	Timestamp time.Time
}

// SetTimestamp sets the timestamp
func (t *TimeInfo) SetTimestamp(timestamp time.Time) {
	t.Timestamp = timestamp
}

// Age gets seconds since timestamp
func (t *TimeInfo) Age() float64 {
	if t.Timestamp == (time.Time{}) {
		return -1
	}
	return time.Since(t.Timestamp).Seconds()
}
