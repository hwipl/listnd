package cmd

// vlanInfo stores vlan information
type vlanInfo struct {
	timeInfo
	vlan    uint16
	packets int
}
