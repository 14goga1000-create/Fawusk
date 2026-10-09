package main

import (
	"fmt"
	"os"
)

// Linux command-line validation utility. The graphical app targets Windows.
func main() {
	if len(os.Args) > 1 && os.Args[1] == "--scan-customav" {
		os.Exit(runAVCLI(os.Args[1:]))
	}
	fmt.Fprintln(os.Stderr, "Fawusk GUI is for Windows. Use --scan-customav archive [--report report.json] for the native validation tool.")
	os.Exit(64)
}
