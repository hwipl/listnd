package cmd

import (
	"bytes"
	"os"
	"testing"

	"github.com/hwipl/listnd/internal/dev"
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
	debugMode = true
	debug("debug test message")
	want = "debug test message\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test without debug mode
	buf.Reset()
	debugMode = false
	debug("debug test message")
	want = ""
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}

func TestPrintTable(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	devices = dev.DeviceMap{}
	devices.Print(&buf)
	want = "=================================================" +
		"=====================\n" +
		"Devices: 0                                       " +
		"(pkts: 0)\n" +
		"=================================================" +
		"=====================\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
