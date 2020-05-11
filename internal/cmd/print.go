package cmd

import (
	"fmt"
	"io"
	"os"
	"time"
)

// debug prints debug output if in debug mode
func debug(text string) {
	if debugMode {
		fmt.Println(text)
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
		device.vlans.Len() == 0 &&
		device.vxlans.Len() == 0 &&
		device.geneves.Len() == 0 {
		return
	}
	// start with header
	fmt.Fprintf(w, propsHeader)

	// print device properties
	device.bridge.Print(w)
	device.dhcp.Print(w)
	device.router.Print(w)
	device.prefixes.Print(w)
	device.powerline.Print(w)
	device.vlans.Print(w)
	device.vxlans.Print(w)
	device.geneves.Print(w)
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
		device.ucasts.Print(w)
		device.mcasts.Print(w)
		device.macPeers.Print(w)
		device.ipPeers.Print(w)
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
