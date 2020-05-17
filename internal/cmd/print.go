package cmd

import (
	"fmt"
	"os"
	"time"
)

// debug prints debug output if in debug mode
func debug(text string) {
	if debugMode {
		fmt.Println(text)
	}
}

// printConsole prints the device table periodically to the console
func printConsole() {
	for {
		// wait 5 seconds before printing
		time.Sleep(5 * time.Second)

		// print devices
		devices.Lock()
		devices.Print(os.Stdout)
		devices.Unlock()
	}

}
