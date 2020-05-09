package cmd

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// deviceInfo is a device found on the network
type deviceInfo struct {
	timeInfo
	mac       gopacket.Endpoint
	vlans     map[uint16]*vlanInfo
	vxlans    map[uint32]*vxlanInfo
	geneves   map[uint32]*geneveInfo
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
		vlan := vlanInfo{}
		vlan.vlan = vlanID
		d.vlans[vlanID] = &vlan
	}
}

// addVxlan adds a vxlan to a device
func (d *deviceInfo) addVxlan(vni uint32) {
	// add entry if it does not et
	if d.vxlans[vni] == nil {
		debug("Adding new vxlan to an entry")
		vxlan := vxlanInfo{}
		vxlan.vxlan = vni
		d.vxlans[vni] = &vxlan
	}
}

// addGeneve adds a geneve to a device
func (d *deviceInfo) addGeneve(vni uint32) {
	// add entry if it does not exist
	if d.geneves[vni] == nil {
		debug("Adding new geneve to an entry")
		geneve := geneveInfo{}
		geneve.geneve = vni
		d.geneves[vni] = &geneve
	}
}

// addPeer adds a peer address to a device
func (d *deviceInfo) addPeer(addr gopacket.Endpoint) {
	switch addr.EndpointType() {
	case layers.EndpointMAC:
		debug("Adding new mac peer to an entry")
		d.macPeers.Add(addr)
	case layers.EndpointIPv4, layers.EndpointIPv6:
		debug("Adding new ip peer to an entry")
		d.ipPeers.Add(addr)
	}
}
