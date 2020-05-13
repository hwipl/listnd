package dev

import (
	"fmt"
	"io"
	"os"
)

var (
	debugMode bool
	debugOut  io.Writer = os.Stdout
)

// debug prints debug output if in debug mode
func debug(text string) {
	if debugMode {
		fmt.Fprintln(debugOut, text)
	}
}

// SetDebug enables or disables debug output
func SetDebug(enable bool) {
	debugMode = enable
}
