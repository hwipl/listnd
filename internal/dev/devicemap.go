package dev

import (
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/gopacket/gopacket"
)

// DeviceMap is the device table definition
type DeviceMap struct {
	sync.Mutex
	Packets int
	m       map[gopacket.Endpoint]*DeviceInfo
}

// Add adds a device to the device table and returns the new device info entry
func (d *DeviceMap) Add(linkAddr gopacket.Endpoint) *DeviceInfo {
	// create map if necessary
	if d.m == nil {
		d.m = make(map[gopacket.Endpoint]*DeviceInfo)
	}
	// create table entries if necessary
	if d.m[linkAddr] == nil {
		debug("Adding new entry")
		device := DeviceInfo{}
		device.MAC = linkAddr
		device.Powerline.Name = "Powerline"
		device.Bridge.Name = "Bridge"
		device.DHCP.Name = "DHCP Server"
		device.Router.Name = "Router"
		device.UCasts.Name = "Unicast Addresses"
		device.MCasts.Name = "Multicast Addresses"
		device.MACPeers.Name = "MAC Peers"
		device.IPPeers.Name = "IP Peers"
		d.m[linkAddr] = &device
	}
	return d.m[linkAddr]
}

// Get returns device information for device with linkAddr
func (d *DeviceMap) Get(linkAddr gopacket.Endpoint) *DeviceInfo {
	if d == nil {
		return nil
	}
	if d.m[linkAddr] == nil {
		return nil
	}
	return d.m[linkAddr]
}

// Reset deletes all device information entries
func (d *DeviceMap) Reset() {
	d.m = nil
}

// Print prints all devices to w
func (d *DeviceMap) Print(w io.Writer) {
	devicesFmt := "===================================" +
		"===================================\n" +
		"Devices: %-39d (pkts: %d)\n" +
		"===================================" +
		"===================================\n"
	fmt.Fprintf(w, devicesFmt, len(d.m), d.Packets)

	// sort devices by mac address
	var macs []gopacket.Endpoint
	for i := range d.m {
		macs = append(macs, i)
	}
	sort.Slice(macs, func(i, j int) bool {
		return macs[i].LessThan(macs[j])
	})

	// print sorted devices
	for _, mac := range macs {
		d.m[mac].Print(w)
		fmt.Fprintln(w)
	}
}
