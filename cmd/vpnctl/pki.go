// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/controller"
	"vpnctl/internal/pki"
)

func runControllerPKI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("pki subcommand required: status|trust|revoke|ca-prepare|ca-activate|ca-retire|ca-rollback|backup|restore")
	}
	fs := flag.NewFlagSet("controller pki "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "", "controller YAML configuration")
	fingerprint := fs.String("fingerprint", "", "certificate SHA-256 fingerprint")
	outPath := fs.String("out", "", "backup output file (contains private keys)")
	inPath := fs.String("file", "", "backup file to restore")
	dataDir := fs.String("data-dir", "", "fresh restore destination")
	configOut := fs.String("config-out", "", "restored YAML config output")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if args[0] == "restore" {
		if *inPath == "" || *dataDir == "" || *configOut == "" {
			return fmt.Errorf("restore requires --file, --data-dir and --config-out")
		}
		if _, err := os.Stat(*configOut); err == nil {
			return fmt.Errorf("config-out already exists")
		} else if !os.IsNotExist(err) {
			return err
		}
		data, err := os.ReadFile(*inPath)
		if err != nil {
			return err
		}
		cfg, err := controller.RestoreBackup(data, *dataDir)
		if err != nil {
			return err
		}
		if err := config.Save(*configOut, cfg); err != nil {
			return fmt.Errorf("data restored, but writing restored config failed: %w", err)
		}
		fmt.Fprintln(os.Stdout, "controller state restored; inspect configuration before starting")
		return nil
	}
	operation := ""
	switch args[0] {
	case "status", "trust":
		operation = "pki.status"
	case "revoke":
		if *fingerprint == "" {
			return fmt.Errorf("--fingerprint is required")
		}
		operation = "pki.revoke"
	case "ca-prepare", "ca-activate", "ca-retire", "ca-rollback":
		operation = strings.Replace(args[0], "ca-", "ca.", 1)
	case "backup":
		if *outPath == "" {
			return fmt.Errorf("--out is required")
		}
		operation = "pki.backup"
	default:
		return fmt.Errorf("unknown PKI subcommand %q", args[0])
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Controller == nil {
		return fmt.Errorf("controller config required")
	}
	response, err := api.Admin(context.Background(), cfg.Controller.DataDir, api.AdminRequest{Operation: operation, Fingerprint: *fingerprint})
	if err != nil {
		return err
	}
	if args[0] == "backup" {
		if err := pki.WriteAtomic(*outPath, response.Backup, 0600); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "controller backup saved")
		return nil
	}
	if args[0] == "trust" {
		fmt.Fprint(os.Stdout, response.PKI.CACert)
		return nil
	}
	return json.NewEncoder(os.Stdout).Encode(response.PKI)
}
