package cmd

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	// helper variables for checking if IP address in endpoint is valid
	// TODO: check
	addrZero     gopacket.Endpoint
	addrUnspecv4 = layers.NewIPEndpoint(net.ParseIP("0.0.0.0"))
	addrUnspecv6 = layers.NewIPEndpoint(net.ParseIP("::"))
)

// isValidAddr checks if address is valid
func isValidAddr(address gopacket.Endpoint) bool {
	if address == addrZero {
		return false
	}

	switch address.EndpointType() {
	case layers.EndpointIPv4:
		if address != addrUnspecv4 {
			return true
		}
	case layers.EndpointIPv6:
		if address != addrUnspecv6 {
			return true
		}
	case layers.EndpointMAC:
		return true
	}
	return false
}

// AddrMap stores mappings of ip/mac addresses to address info
type AddrMap struct {
	m map[gopacket.Endpoint]*AddrInfo
}

// Add adds address to the AddrMap and returns the address info
func (a *AddrMap) Add(address gopacket.Endpoint) *AddrInfo {
	// check if address is valid
	if !isValidAddr(address) {
		return nil
	}

	// create map if necessary
	if a.m == nil {
		a.m = make(map[gopacket.Endpoint]*AddrInfo)
	}
	// create table entry if necessary
	if a.m[address] == nil {
		debug("Adding new address entry")
		addr := AddrInfo{
			Addr: address,
		}
		a.m[address] = &addr
	}
	return a.m[address]
}

// Get returns address info with address
func (a *AddrMap) Get(address gopacket.Endpoint) *AddrInfo {
	if a.m == nil {
		return nil
	}
	return a.m[address]
}

// Del removes the address info with address
func (a *AddrMap) Del(address gopacket.Endpoint) {
	// check if address is valid
	if !isValidAddr(address) {
		return
	}

	// remove entry if it exists
	if a.m[address] != nil {
		debug("Deleting address entry")
		delete(a.m, address)
	}
}
