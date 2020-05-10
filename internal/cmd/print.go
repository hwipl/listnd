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

// printProperties prints device properties in device table
func printProperties(w io.Writer, device *deviceInfo) {
	propsHeader := "  Properties:\n"

	// make sure any properties are present
	if !device.bridge.isEnabled() &&
		!device.dhcp.isEnabled() &&
		!device.router.isEnabled() &&
		!device.powerline.isEnabled() &&
		len(device.vlans.m) == 0 &&
		len(device.vxlans.m) == 0 &&
		len(device.geneves.m) == 0 {
		return
	}
	// start with header
	fmt.Fprintf(w, propsHeader)

	// print device properties
	printBridge(w, device)
	printDhcp(w, device)
	printRouter(w, device)
	printPowerline(w, device)
	device.vlans.Print(w)
	device.vxlans.Print(w)
	device.geneves.Print(w)
}

// printPeers prints peer addresses in device table
func printPeers(w io.Writer, device *deviceInfo) {
	macPeersHeader := "  MAC Peers:\n"
	ipPeersHeader := "  IP Peers:\n"

	if len(device.macPeers.m) > 0 {
		fmt.Fprintf(w, macPeersHeader)
		for _, info := range device.macPeers.m {
			fmt.Fprintf(w, "    %s\n", info)
		}
	}

	if len(device.ipPeers.m) > 0 {
		fmt.Fprintf(w, ipPeersHeader)
		for _, info := range device.ipPeers.m {
			fmt.Fprintf(w, "    %s\n", info)
		}
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
		device.ips.Print(w)
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
