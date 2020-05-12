package dev

import (
	"fmt"
	"io"
)

// PropInfo is a device property
type PropInfo struct {
	TimeInfo
	Name    string
	Enabled bool
}

// Enable enables the device property
func (p *PropInfo) Enable() {
	p.Enabled = true
}

// Disable disables the device property
func (p *PropInfo) Disable() {
	p.Enabled = false
}

// IsEnabled checks if device property is enabled
func (p *PropInfo) IsEnabled() bool {
	if p != nil && p.Enabled {
		return true
	}
	return false
}

// Print prints the property info to w
func (p *PropInfo) Print(w io.Writer) {
	if !p.Enabled {
		return
	}
	propFmt := "    %s: %-*t (age: %.f)\n"
	padLen := 42 - len(p.Name)
	fmt.Fprintf(w, propFmt, p.Name, padLen, p.Enabled, p.Age())
}
