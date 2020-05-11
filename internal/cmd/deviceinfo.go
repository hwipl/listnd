package cmd

import (
	"fmt"
	"io"

	"github.com/google/gopacket"
)

// deviceInfo is a device found on the network
type deviceInfo struct {
	timeInfo
	mac       gopacket.Endpoint
	vlans     vnetMap
	vxlans    vnetMap
	geneves   vnetMap
	powerline propInfo
	bridge    propInfo
	dhcp      propInfo
	router    propInfo
	prefixes  prefixList
	packets   int
	ucasts    AddrMap
	mcasts    AddrMap
	macPeers  AddrMap
	ipPeers   AddrMap
}

// Print prints the device to w
func (d *deviceInfo) Print(w io.Writer) {
	// print MAC address
	macFmt := "MAC: %-43s (age: %.f, pkts: %d)\n"
	fmt.Fprintf(w, macFmt, d.mac, d.getAge(), d.packets)

	// print properties
	propsHeader := "  Properties:\n"
	if d.bridge.isEnabled() ||
		d.dhcp.isEnabled() ||
		d.router.isEnabled() ||
		d.powerline.isEnabled() ||
		d.vlans.Len() > 0 ||
		d.vxlans.Len() > 0 ||
		d.geneves.Len() > 0 {

		// start with header
		fmt.Fprintf(w, propsHeader)

		// print device properties
		d.bridge.Print(w)
		d.dhcp.Print(w)
		d.router.Print(w)
		d.prefixes.Print(w)
		d.powerline.Print(w)
		d.vlans.Print(w)
		d.vxlans.Print(w)
		d.geneves.Print(w)
	}

	// print addresses
	d.ucasts.Print(w)
	d.mcasts.Print(w)
	d.macPeers.Print(w)
	d.ipPeers.Print(w)
}
