package cmd

import (
	"fmt"
	"net"

	"github.com/google/gopacket/layers"
)

// prefixInfo stores a router's prefix information
type prefixInfo struct {
	timeInfo
	prefix layers.ICMPv6Option
}

// String converts the prefix to a string
func (p *prefixInfo) String() string {
	prefixFmt := "Prefix: %-34s (age: %.f)"
	pfLen := uint8(p.prefix.Data[0])
	pf := net.IP(p.prefix.Data[14:])
	ps := fmt.Sprintf("%v/%v", pf, pfLen)
	return fmt.Sprintf(prefixFmt, ps, p.getAge())
}
