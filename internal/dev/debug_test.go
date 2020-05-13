package dev

import (
	"bytes"
	"os"
	"testing"
)

func TestDebug(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// redirect output to buffer
	debugOut = &buf
	defer func() {
		debugOut = os.Stdout
	}()

	// test with debug mode
	SetDebug(true)
	debug("debug test message")
	want = "debug test message\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test without debug mode
	buf.Reset()
	SetDebug(false)
	debug("debug test message")
	want = ""
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
