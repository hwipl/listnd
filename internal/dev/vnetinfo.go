package dev

import "fmt"

// VNetInfo stores virtual network information
type VNetInfo struct {
	TimeInfo
	Type    string
	ID      uint32
	Packets int
}

// String converts vnet info to a string
func (v *VNetInfo) String() string {
	vnetFmt := "%s: %-*d (age: %.f, pkts: %d)"
	padLen := 42 - len(v.Type)
	return fmt.Sprintf(vnetFmt, v.Type, padLen, v.ID, v.Age(),
		v.Packets)
}
