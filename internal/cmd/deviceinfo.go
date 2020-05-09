package cmd

import (
	"github.com/google/gopacket"
)

// deviceInfo is a device found on the network
type deviceInfo struct {
	timeInfo
	mac       gopacket.Endpoint
	vlans     map[uint16]*vnetInfo
	vxlans    map[uint32]*vnetInfo
	geneves   map[uint32]*vnetInfo
	powerline powerlineInfo
	bridge    bridgeInfo
	dhcp      dhcpInfo
	router    routerInfo
	packets   int
	ips       AddrMap
	macPeers  AddrMap
	ipPeers   AddrMap
}

// addVlan adds a vlan to a device
func (d *deviceInfo) addVlan(vlanID uint16) {
	// add entry if it does not exist
	if d.vlans[vlanID] == nil {
		debug("Adding new vlan to an entry")
		vlan := vnetInfo{}
		vlan.ID = uint32(vlanID)
		d.vlans[vlanID] = &vlan
	}
}

// addVxlan adds a vxlan to a device
func (d *deviceInfo) addVxlan(vni uint32) {
	// add entry if it does not et
	if d.vxlans[vni] == nil {
		debug("Adding new vxlan to an entry")
		vxlan := vnetInfo{}
		vxlan.ID = vni
		d.vxlans[vni] = &vxlan
	}
}

// addGeneve adds a geneve to a device
func (d *deviceInfo) addGeneve(vni uint32) {
	// add entry if it does not exist
	if d.geneves[vni] == nil {
		debug("Adding new geneve to an entry")
		geneve := vnetInfo{}
		geneve.ID = vni
		d.geneves[vni] = &geneve
	}
}
