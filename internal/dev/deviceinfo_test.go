package dev

import (
	"bytes"
	"log"
	"net"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func TestDeviceInfo(t *testing.T) {
	var d DeviceInfo
	var buf bytes.Buffer
	var want, got string

	// test empty
	d.Print(&buf)
	want = "MAC: []                                          " +
		"(age: -1, pkts: 0)\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
	buf.Reset()

	// test filled
	// set mac
	mac, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		log.Fatal(err)
	}
	d.MAC = layers.NewMACEndpoint(mac)

	// set vnets
	// vlan
	vlan := d.VLANs.Add(42)
	vlan.Type = "VLAN"
	vlan.ID = 42
	vlan.Packets = 1
	// vxlan
	vxlan := d.VXLANs.Add(43)
	vxlan.Type = "VXLAN"
	vxlan.ID = 43
	vxlan.Packets = 2
	// geneve
	geneve := d.GENEVEs.Add(44)
	geneve.Type = "GENEVE"
	geneve.ID = 44
	geneve.Packets = 3

	// set properties
	d.Powerline.Name = "Powerline"
	d.Powerline.Enable()
	d.Bridge.Name = "Bridge"
	d.Bridge.Enable()
	d.DHCP.Name = "DHCP Server"
	d.DHCP.Enable()
	d.Router.Name = "Router"
	d.Router.Enable()

	// set prefix
	d.Prefixes.Add(testICMPv6OptPrefixInfo)

	// set packet counter
	d.Packets = 128

	// set addresses
	// unicast
	d.UCasts.Name = "Unicast Addresses"
	ipv4 := layers.NewIPEndpoint(net.ParseIP("127.0.0.1"))
	d.UCasts.Add(ipv4)
	// multicast
	d.MCasts.Name = "Multicast Addresses"
	mcast := net.ParseIP("ff02::1")
	d.MCasts.Add(layers.NewIPEndpoint(mcast))
	// mac peer
	d.MACPeers.Name = "MAC Peers"
	d.MACPeers.Add(d.MAC)
	// ip peer
	d.IPPeers.Name = "IP Peers"
	d.IPPeers.Add(ipv4)

	// test
	d.Print(&buf)
	want = "MAC: 00:00:5e:00:53:01                           " +
		"(age: -1, pkts: 128)\n" +
		"  Properties:\n" +
		"    Bridge: true                                 " +
		"(age: -1)\n" +
		"    DHCP Server: true                            " +
		"(age: -1)\n" +
		"    Router: true                                 " +
		"(age: -1)\n" +
		"      Prefix: 2001:db8:0:1::/64                  " +
		"(age: -1)\n" +
		"    Powerline: true                              " +
		"(age: -1)\n" +
		"    VLAN: 42                                     " +
		"(age: -1, pkts: 1)\n" +
		"    VXLAN: 43                                    " +
		"(age: -1, pkts: 2)\n" +
		"    GENEVE: 44                                   " +
		"(age: -1, pkts: 3)\n" +
		"  Unicast Addresses:\n" +
		"    IP: 127.0.0.1                                " +
		"(age: -1, pkts: 0)\n" +
		"  Multicast Addresses:\n" +
		"    IP: ff02::1                                  " +
		"(age: -1, pkts: 0)\n" +
		"  MAC Peers:\n" +
		"    MAC: 00:00:5e:00:53:01                       " +
		"(age: -1, pkts: 0)\n" +
		"  IP Peers:\n" +
		"    IP: 127.0.0.1                                " +
		"(age: -1, pkts: 0)\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}
