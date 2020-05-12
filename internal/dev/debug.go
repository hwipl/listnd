package dev

import "fmt"

var (
	debugMode bool
)

// debug prints debug output if in debug mode
func debug(text string) {
	if debugMode {
		fmt.Println(text)
	}
}

// SetDebug enables or disables debug output
func SetDebug(enable bool) {
	debugMode = enable
}
