//go:build linux && vpnctl_profile

package main

import (
	"fmt"
	"os"

	"vpnctl/internal/selectorprofile"
)

func init() {
	directory := os.Getenv("VPNCTL_SELECTOR_PROFILE_DIR")
	if directory == "" || !selectorProfileCommand(os.Getenv("VPNCTL_VM_WORKER"), os.Args[1:]) {
		return
	}
	if err := selectorprofile.Start(directory); err != nil {
		// Fixed error categories only; no paths, arguments or credentials.
		fmt.Fprintln(os.Stderr, "selector profile unavailable:", err)
	}
}

func selectorProfileCommand(worker string, args []string) bool {
	if worker != "1" || len(args) < 7 || args[0] != "node" || args[1] != "relay" || args[2] != "target" || args[3] != "reconcile" {
		return false
	}
	// Match the exact fixture command syntax, including one app2 target and
	// watch flag. Other commands and duplicate/alternate target flags are off.
	targets, watch := 0, false
	for i := 4; i < len(args); i++ {
		switch args[i] {
		case "--target-id":
			if i+1 >= len(args) || args[i+1] != "app2" {
				return false
			}
			targets++
			i++
		case "--watch":
			watch = true
		default:
			if len(args[i]) >= len("--target-id=") && args[i][:len("--target-id=")] == "--target-id=" {
				return false
			}
		}
	}
	return targets == 1 && watch
}
