package cmd

// propInfo is a device property
type propInfo struct {
	timeInfo
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
