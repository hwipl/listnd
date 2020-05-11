package cmd

import (
	"fmt"
	"io"
)

// propInfo is a device property
type propInfo struct {
	timeInfo
	name    string
	enabled bool
}

// enable enables the device property
func (p *propInfo) enable() {
	p.enabled = true
}

// disable disables the device property
func (p *propInfo) disable() {
	p.enabled = false
}

// isEnabled checks if device property is enabled
func (p *propInfo) isEnabled() bool {
	if p != nil && p.enabled {
		return true
	}
	return false
}

// Print prints the property info to w
func (p *propInfo) Print(w io.Writer) {
	if !p.enabled {
		return
	}
	propFmt := "    %s: %-*t (age: %.f)\n"
	padLen := 42 - len(p.name)
	fmt.Fprintf(w, propFmt, p.name, padLen, p.enabled, p.getAge())
}
