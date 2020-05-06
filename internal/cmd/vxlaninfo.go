package cmd

// vxlanInfo stores vxlan information
type vxlanInfo struct {
	timeInfo
	vxlan   uint32
	packets int
}
