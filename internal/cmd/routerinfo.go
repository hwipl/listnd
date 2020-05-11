package cmd

import "github.com/google/gopacket/layers"

// routerInfo stores router information of a device on the network
type routerInfo struct {
	propInfo
	prefixes []*prefixInfo
}

// clearPrefixes clears prefixes in router info
func (r *routerInfo) clearPrefixes() {
	r.prefixes = nil
}

// addPrefix adds a prefix to router info
func (r *routerInfo) addPrefix(prefix layers.ICMPv6Option) *prefixInfo {
	p := prefixInfo{}
	p.prefix = prefix
	r.prefixes = append(r.prefixes, &p)
	return &p
}

// getPrefixes gets prefixes from router info
func (r *routerInfo) getPrefixes() []*prefixInfo {
	return r.prefixes
}
