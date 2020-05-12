package cmd

import (
	"fmt"
	"io"

	"github.com/google/gopacket"
)

// DeviceInfo is a device found on the network
type DeviceInfo struct {
	timeInfo
	MAC       gopacket.Endpoint
	VLANs     vnetMap
	VXLANs    vnetMap
	GENEVEs   vnetMap
	Powerline propInfo
	Bridge    propInfo
	DHCP      propInfo
	Router    propInfo
	Prefixes  PrefixList
	Packets   int
	UCasts    AddrMap
	MCasts    AddrMap
	MACPeers  AddrMap
	IPPeers   AddrMap
}

// Print prints the device to w
func (d *DeviceInfo) Print(w io.Writer) {
	// print MAC address
	macFmt := "MAC: %-43s (age: %.f, pkts: %d)\n"
	fmt.Fprintf(w, macFmt, d.MAC, d.getAge(), d.Packets)

	// print properties
	propsHeader := "  Properties:\n"
	if d.Bridge.isEnabled() ||
		d.DHCP.isEnabled() ||
		d.Router.isEnabled() ||
		d.Powerline.isEnabled() ||
		d.VLANs.Len() > 0 ||
		d.VXLANs.Len() > 0 ||
		d.GENEVEs.Len() > 0 {

		// start with header
		fmt.Fprintf(w, propsHeader)

		// print device properties
		d.Bridge.Print(w)
		d.DHCP.Print(w)
		d.Router.Print(w)
		d.Prefixes.Print(w)
		d.Powerline.Print(w)
		d.VLANs.Print(w)
		d.VXLANs.Print(w)
		d.GENEVEs.Print(w)
	}

	// print addresses
	d.UCasts.Print(w)
	d.MCasts.Print(w)
	d.MACPeers.Print(w)
	d.IPPeers.Print(w)
}
