package cmd

import (
	"fmt"
	"io"
	"os"
	"time"
)

var (
	debugOut io.Writer = os.Stdout
)

// debug prints debug output if in debug mode
func debug(text string) {
	if debugMode {
		fmt.Fprintln(debugOut, text)
	}
}

// printTable prints the device table
func printTable() {
	devices.Lock()
	devices.Print(os.Stdout)
	devices.Unlock()
}

// printConsole prints the device table periodically to the console
func printConsole() {
	go func() {
		for {
			// wait 5 seconds before printing
			time.Sleep(time.Duration(interval) * time.Second)

			// print devices
			printTable()
		}
	}()

}
