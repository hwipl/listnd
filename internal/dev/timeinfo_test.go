package dev

import (
	"testing"
	"time"
)

func TestTimeInfo(t *testing.T) {
	var i TimeInfo
	var want, got float64

	// test default
	want = -1
	got = i.Age()
	if got != want {
		t.Errorf("got = %f; want %f", got, want)
	}

	// test SetTimestamp()
	now := time.Now()
	i.SetTimestamp(now)
	if i.Timestamp != now {
		t.Errorf("i.Timestamp = %s; want %s", i.Timestamp, now)
	}

	// test Age()
	age := i.Age()
	diff := time.Since(now).Seconds() - age
	if diff < 0 || diff > 1 {
		t.Errorf("diff = %.10f; want diff > 0 && diff < 1", diff)
	}
}
