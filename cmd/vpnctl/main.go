package main

import (
	"fmt"
	"os"
)

const usage = `vpnctl - minimal VPN control-plane + metrics (MVP)

Usage:
  vpnctl controller init --listen <addr>
  vpnctl node join --controller <addr> --name <name> [--direct auto|off]
  vpnctl node add --name <name> --pubkey <key> --endpoint <ip:port>
  vpnctl up
  vpnctl down
  vpnctl discover
  vpnctl direct status
  vpnctl direct test --peer <name>
  vpnctl direct force --peer <name> --on|--off
  vpnctl ping --all|--peer <name>
  vpnctl perf --duration <s>
  vpnctl stats --window <m>
  vpnctl export csv --out <file>
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Print(usage)
	case "controller":
		handleController(os.Args[2:])
	case "node":
		handleNode(os.Args[2:])
	case "up", "down", "discover", "ping", "perf", "stats", "export", "direct":
		fmt.Fprintf(os.Stderr, "command %q not implemented yet\n", cmd)
		os.Exit(2)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func handleController(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, "controller subcommand required\n")
		os.Exit(2)
	}
	if args[0] != "init" {
		fmt.Fprintf(os.Stderr, "unknown controller subcommand %q\n", args[0])
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "controller init not implemented yet")
	os.Exit(2)
}

func handleNode(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, "node subcommand required\n")
		os.Exit(2)
	}
	if args[0] != "join" && args[0] != "add" {
		fmt.Fprintf(os.Stderr, "unknown node subcommand %q\n", args[0])
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "node subcommand not implemented yet")
	os.Exit(2)
}

