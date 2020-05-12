package dev

import (
	"fmt"
	"io"
	"sync"

	"github.com/google/gopacket"
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

// Print prints all devices to w
func (d *DeviceMap) Print(w io.Writer) {
	devicesFmt := "===================================" +
		"===================================\n" +
		"Devices: %-39d (pkts: %d)\n" +
		"===================================" +
		"===================================\n"
	fmt.Fprintf(w, devicesFmt, len(d.m), d.Packets)
	for _, device := range d.m {
		device.Print(w)
		fmt.Fprintln(w)
	}
}
