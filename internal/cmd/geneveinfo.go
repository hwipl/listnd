package cmd

// geneveInfo stores geneve information
// TODO: common vnetInfo for vlan, vxlan, geneve?
type geneveInfo struct {
	timeInfo
	geneve  uint32
	packets int
}
