package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

// Same CustomAV pipeline as the GUI; no separate detector or shell command.
func runAVCLI(args []string) int {
	if len(args) != 2 && len(args) != 4 {
		fmt.Fprintln(os.Stderr, "Usage: Fawusk --scan-customav archive.faw [--report new-report.json]")
		return 64
	}
	if len(args) == 4 && args[2] != "--report" {
		return 64
	}
	r := scanSecurity(context.Background(), args[1], nil)
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return 3
	}
	b = append(b, '\n')
	if len(args) == 4 {
		f, e := os.OpenFile(args[3], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 3
		}
		_, e = f.Write(b)
		ce := f.Close()
		if e != nil || ce != nil {
			return 3
		}
	} else {
		if _, e := os.Stdout.Write(b); e != nil {
			return 3
		}
	}
	if r.blocked() {
		return 2
	}
	if !r.Complete {
		return 3
	}
	return 0
}
