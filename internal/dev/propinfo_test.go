package dev

import (
	"bytes"
	"testing"
)

func TestPropInfo(t *testing.T) {
	var p PropInfo
	var buf bytes.Buffer
	var want, got string

	// test default
	if p.IsEnabled() {
		t.Errorf("p.IsEnabled() = true; want false")
	}
	p.Print(&buf)
	want = ""
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
	buf.Reset()

	// test enable
	p.Name = "TestProp"
	p.Enable()
	if !p.IsEnabled() {
		t.Errorf("p.IsEnabled() = false; want true")
	}
	p.Print(&buf)
	want = "    TestProp: true                               (age: -1)\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
	buf.Reset()

	// test disable
	p.Disable()
	if p.IsEnabled() {
		t.Errorf("p.IsEnabled() = true; want false")
	}
	p.Print(&buf)
	want = ""
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
	buf.Reset()
}
