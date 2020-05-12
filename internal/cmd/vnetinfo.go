package cmd

import "fmt"

// vnetInfo stores virtual network information
type vnetInfo struct {
	TimeInfo
	Type    string
	ID      uint32
	packets int
}

// String converts vnet info to a string
func (v *vnetInfo) String() string {
	vnetFmt := "$s: %-*d (age: %.f, pkts: %d)"
	padLen := 44 - len(v.Type)
	return fmt.Sprintf(vnetFmt, padLen, v.Type, v.ID, v.Age(),
		v.packets)
}
