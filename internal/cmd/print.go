package cmd

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// debug prints debug output if in debug mode
func debug(text string) {
	if debugMode {
		fmt.Println(text)
	}
}

// printRouter prints router information in device table
func printRouter(w io.Writer, device *deviceInfo) {
	routerFmt := "    Router: %-36t (age: %.f)\n"
	prefixFmt := "      Prefix: %-34s (age: %.f)\n"

	if !device.router.isEnabled() {
		return
	}
	fmt.Fprintf(w, routerFmt, device.router.isEnabled(),
		device.router.getAge())
	for _, prefix := range device.router.getPrefixes() {
		pLen := uint8(prefix.prefix.Data[0])
		p := net.IP(prefix.prefix.Data[14:])
		ps := fmt.Sprintf("%v/%v", p, pLen)
		fmt.Fprintf(w, prefixFmt, ps, prefix.getAge())
	}
}

// printDhcp prints dhcp information in device table
func printDhcp(w io.Writer, device *deviceInfo) {
	dhcpFmt := "    DHCP: %-38s (age: %.f)\n"
	dhcpRole := "server"

	if !device.dhcp.isEnabled() {
		return
	}
	fmt.Fprintf(w, dhcpFmt, dhcpRole, device.dhcp.getAge())
}

// printBridge prints bridge information in device table
func printBridge(w io.Writer, device *deviceInfo) {
	bridgeFmt := "    Bridge: %-36t (age: %.f)\n"

	if !device.bridge.isEnabled() {
		return
	}
	fmt.Fprintf(w, bridgeFmt, device.bridge.isEnabled(),
		device.bridge.getAge())
}

// printPowerline prints powerline information in device table
func printPowerline(w io.Writer, device *deviceInfo) {
	powerlineFmt := "    Powerline: %-33t (age: %.f)\n"

	if !device.powerline.isEnabled() {
		return
	}
	fmt.Fprintf(w, powerlineFmt, device.powerline.isEnabled(),
		device.powerline.getAge())
}

// printVlans prints vlan information in device table
func printVlans(w io.Writer, device *deviceInfo) {
	vlanFmt := "    VLAN: %-38d (age: %.f, pkts: %d)\n"

	if len(device.vlans) == 0 {
		return
	}
	for _, vlan := range device.vlans {
		// print VLAN info
		fmt.Fprintf(w, vlanFmt, vlan.vlan, vlan.getAge(),
			vlan.packets)
	}
}

// printVxlans prints vxlan information in device table
func printVxlans(w io.Writer, device *deviceInfo) {
	vxlanFmt := "    VXLAN: %-37d (age: %.f, pkts: %d)\n"

	if len(device.vxlans) == 0 {
		return
	}
	for _, vxlan := range device.vxlans {
		// print VXLAN info
		fmt.Fprintf(w, vxlanFmt, vxlan.vxlan, vxlan.getAge(),
			vxlan.packets)
	}
}

// printGeneves prints geneve information in device table
func printGeneves(w io.Writer, device *deviceInfo) {
	geneveFmt := "    Geneve: %-36d (age: %.f, pkts: %d)\n"

	if len(device.geneves) == 0 {
		return
	}
	for _, geneve := range device.geneves {
		// print Geneve info
		fmt.Fprintf(w, geneveFmt, geneve.ID, geneve.getAge(),
			geneve.packets)
	}
}

// printProperties prints device properties in device table
func printProperties(w io.Writer, device *deviceInfo) {
	propsHeader := "  Properties:\n"

	// make sure any properties are present
	if !device.bridge.isEnabled() &&
		!device.dhcp.isEnabled() &&
		!device.router.isEnabled() &&
		!device.powerline.isEnabled() &&
		len(device.vlans) == 0 &&
		len(device.vxlans) == 0 &&
		len(device.geneves) == 0 {
		return
	}
	// start with header
	fmt.Fprintf(w, propsHeader)

	// print device properties
	printBridge(w, device)
	printDhcp(w, device)
	printRouter(w, device)
	printPowerline(w, device)
	printVlans(w, device)
	printVxlans(w, device)
	printGeneves(w, device)
}

// _printIps prints ip information in device table
func _printIps(w io.Writer, ips []*AddrInfo) {
	ipFmt := "    IP: %-40s (age: %.f, pkts: %d)\n"
	for _, info := range ips {
		fmt.Fprintf(w, ipFmt, info.Addr, info.getAge(), info.Packets)
	}
}

// printIps prints ip addresses in device table
func printIps(w io.Writer, device *deviceInfo) {
	multicastHeader := "  Multicast Addresses:\n"
	unicastHeader := "  Unicast Addresses:\n"
	var multicasts []*AddrInfo
	var unicasts []*AddrInfo

	// search for ucast and mcast addresses
	for ip, info := range device.ips.m {
		if net.IP(ip.Raw()).IsMulticast() {
			multicasts = append(multicasts, info)
			continue
		}
		unicasts = append(unicasts, info)
	}

	// print unicast addresses
	if len(unicasts) > 0 {
		fmt.Fprintf(w, unicastHeader)
		_printIps(w, unicasts)
	}

	// print multicast addresses
	if len(multicasts) > 0 {
		fmt.Fprintf(w, multicastHeader)
		_printIps(w, multicasts)
	}
}

// printPeers prints peer addresses in device table
func printPeers(w io.Writer, device *deviceInfo) {
	macPeersHeader := "  MAC Peers:\n"
	ipPeersHeader := "  IP Peers:\n"

	if len(device.macPeers.m) > 0 {
		var macs []*AddrInfo
		for _, info := range device.macPeers.m {
			macs = append(macs, info)
		}
		fmt.Fprintf(w, macPeersHeader)
		_printIps(w, macs)
	}

	if len(device.ipPeers.m) > 0 {
		var ips []*AddrInfo
		for _, info := range device.ipPeers.m {
			ips = append(ips, info)
		}
		fmt.Fprintf(w, ipPeersHeader)
		_printIps(w, ips)
	}
}

// printDevices prints the device table
func printDevices(w io.Writer) {
	devicesFmt := "===================================" +
		"===================================\n" +
		"Devices: %-39d (pkts: %d)\n" +
		"===================================" +
		"===================================\n"
	macFmt := "MAC: %-43s (age: %.f, pkts: %d)\n"

	// lock devices
	devices.Lock()

	// start with devices header
	fmt.Fprintf(w, devicesFmt, len(devices.m), devices.packets)

	for mac, device := range devices.m {
		// print MAC address
		fmt.Fprintf(w, macFmt, mac, device.getAge(),
			device.packets)
		// print properties and ips
		printProperties(w, device)
		printIps(w, device)
		printPeers(w, device)
		fmt.Fprintln(w)
	}

	// unlock devices
	devices.Unlock()

}

// printConsole prints the device table periodically to the console
func printConsole() {
	for {
		// print devices
		printDevices(os.Stdout)

		// wait 5 seconds before printing
		time.Sleep(5 * time.Second)
	}

}
