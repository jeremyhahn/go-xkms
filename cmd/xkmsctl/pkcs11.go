// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package main

import (
	"fmt"
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/manager"
	"github.com/spf13/cobra"
)

// pkcs11Cmd is the parent command for PKCS#11 token management operations.
var pkcs11Cmd = &cobra.Command{
	Use:   "pkcs11",
	Short: "PKCS#11 token management commands",
	Long: `Manage PKCS#11 tokens and modules.

These commands provide local PKCS#11 token management including module
registration, token initialization, and connection management.

Examples:
  # List available PKCS#11 modules
  xkmsctl pkcs11 probe

  # Register a module
  xkmsctl pkcs11 register --module /usr/lib/softhsm/libsofthsm2.so --name SoftHSM2

  # List registered modules
  xkmsctl pkcs11 list-modules

  # List tokens across all modules
  xkmsctl pkcs11 list-tokens

  # Initialize a new token
  xkmsctl pkcs11 init-token --module-id pkcs11-libsofthsm2 --slot 0 \
    --label "MyToken" --so-pin 12345678 --user-pin 1234`,
}

// pkcs11ProbeCmd detects available PKCS#11 modules on the system.
var pkcs11ProbeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Detect available PKCS#11 modules",
	Long:  "Scan common locations for PKCS#11 libraries and report findings.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		probed := manager.ProbeModulesWithNames()

		if len(probed) == 0 {
			if cfg.OutputFormat == "json" {
				_ = printer.PrintJSON([]interface{}{})
			} else {
				fmt.Println("No PKCS#11 modules found.")
			}
			return
		}

		printVerbose("Found %d PKCS#11 modules", len(probed))

		if cfg.OutputFormat == "json" {
			_ = printer.PrintJSON(probed)
		} else {
			fmt.Println("Available PKCS#11 Modules:")
			fmt.Println()
			for _, m := range probed {
				fmt.Printf("  %s\n", m.DisplayName)
				fmt.Printf("    Path: %s\n", m.LibraryPath)
				fmt.Println()
			}
		}
	},
}

// pkcs11RegisterCmd registers a PKCS#11 module.
var pkcs11RegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a PKCS#11 module",
	Long:  "Register a PKCS#11 library for use with xkms.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		modulePath, _ := cmd.Flags().GetString("module")
		displayName, _ := cmd.Flags().GetString("name")

		if modulePath == "" {
			handleError(fmt.Errorf("--module is required"))
			return
		}

		mgr := manager.New()
		defer func() { _ = mgr.Close() }()

		moduleID, err := mgr.RegisterModule(modulePath, displayName)
		if err != nil {
			handleError(fmt.Errorf("failed to register module: %w", err))
			return
		}

		printVerbose("Registered module: %s", moduleID)

		result := map[string]interface{}{
			"module_id":    moduleID,
			"library_path": modulePath,
			"display_name": displayName,
		}

		if cfg.OutputFormat == "json" {
			_ = printer.PrintJSON(result)
		} else {
			fmt.Printf("Module registered successfully\n")
			fmt.Printf("  Module ID: %s\n", moduleID)
			fmt.Printf("  Library:   %s\n", modulePath)
			if displayName != "" {
				fmt.Printf("  Name:      %s\n", displayName)
			}
		}
	},
}

// pkcs11ListModulesCmd lists registered PKCS#11 modules.
var pkcs11ListModulesCmd = &cobra.Command{
	Use:   "list-modules",
	Short: "List registered PKCS#11 modules",
	Long:  "Display all PKCS#11 modules that have been registered.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		mgr := manager.New()
		defer func() { _ = mgr.Close() }()

		// For this command to be useful, we need to auto-register probed modules
		// since manager state doesn't persist across CLI invocations
		probed := manager.ProbeModulesWithNames()
		for _, p := range probed {
			_, _ = mgr.RegisterModule(p.LibraryPath, p.DisplayName)
		}

		modules := mgr.ListModules()

		if len(modules) == 0 {
			if cfg.OutputFormat == "json" {
				_ = printer.PrintJSON([]interface{}{})
			} else {
				fmt.Println("No PKCS#11 modules registered.")
			}
			return
		}

		if cfg.OutputFormat == "json" {
			_ = printer.PrintJSON(modules)
		} else {
			fmt.Println("Registered PKCS#11 Modules:")
			fmt.Println()
			for _, m := range modules {
				fmt.Printf("  %s (%s)\n", m.DisplayName, m.ID)
				fmt.Printf("    Path:  %s\n", m.LibraryPath)
				fmt.Printf("    State: %s\n", m.State.String())
				if len(m.Slots) > 0 {
					fmt.Printf("    Slots: %d\n", len(m.Slots))
					for _, slot := range m.Slots {
						status := "uninitialized"
						if slot.Initialized {
							status = "initialized"
						}
						if !slot.TokenPresent {
							status = "no token"
						}
						label := slot.Label
						if label == "" {
							label = "(unnamed)"
						}
						fmt.Printf("      Slot %d: %s [%s]\n", slot.SlotID, label, status)
					}
				}
				fmt.Println()
			}
		}
	},
}

// pkcs11ListTokensCmd lists all tokens across registered modules.
var pkcs11ListTokensCmd = &cobra.Command{
	Use:   "list-tokens",
	Short: "List all PKCS#11 tokens",
	Long:  "Display all tokens across all registered PKCS#11 modules.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		mgr := manager.New()
		defer func() { _ = mgr.Close() }()

		// Auto-register probed modules
		probed := manager.ProbeModulesWithNames()
		for _, p := range probed {
			_, _ = mgr.RegisterModule(p.LibraryPath, p.DisplayName)
		}

		tokens := mgr.ListTokens()

		if len(tokens) == 0 {
			if cfg.OutputFormat == "json" {
				_ = printer.PrintJSON([]interface{}{})
			} else {
				fmt.Println("No PKCS#11 tokens found.")
			}
			return
		}

		if cfg.OutputFormat == "json" {
			_ = printer.PrintJSON(tokens)
		} else {
			fmt.Println("PKCS#11 Tokens:")
			fmt.Println()
			for _, t := range tokens {
				label := t.Label
				if label == "" {
					label = "(uninitialized)"
				}
				status := "disconnected"
				if t.Connected {
					status = "connected"
				}
				initStatus := "not initialized"
				if t.Initialized {
					initStatus = "initialized"
				}
				fmt.Printf("  %s (Slot %d)\n", label, t.SlotID)
				fmt.Printf("    Module:       %s (%s)\n", t.ModuleName, t.ModuleID)
				fmt.Printf("    Status:       %s, %s\n", initStatus, status)
				if t.Manufacturer != "" {
					fmt.Printf("    Manufacturer: %s\n", t.Manufacturer)
				}
				if t.Model != "" {
					fmt.Printf("    Model:        %s\n", t.Model)
				}
				if t.Serial != "" {
					fmt.Printf("    Serial:       %s\n", t.Serial)
				}
				fmt.Println()
			}
		}
	},
}

// pkcs11InitTokenCmd initializes a new token.
var pkcs11InitTokenCmd = &cobra.Command{
	Use:   "init-token",
	Short: "Initialize a PKCS#11 token",
	Long: `Initialize a new PKCS#11 token with Security Officer and User PINs.

WARNING: This will erase all data on the token!`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		modulePath, _ := cmd.Flags().GetString("module")
		moduleID, _ := cmd.Flags().GetString("module-id")
		slotID, _ := cmd.Flags().GetUint("slot")
		label, _ := cmd.Flags().GetString("label")
		soPin, _ := cmd.Flags().GetString("so-pin")
		userPin, _ := cmd.Flags().GetString("user-pin")

		if label == "" {
			handleError(fmt.Errorf("--label is required"))
			return
		}
		if soPin == "" {
			handleError(fmt.Errorf("--so-pin is required"))
			return
		}
		if userPin == "" {
			handleError(fmt.Errorf("--user-pin is required"))
			return
		}

		mgr := manager.New()
		defer func() { _ = mgr.Close() }()

		// If module path is provided, register it and use the derived ID
		if modulePath != "" {
			var err error
			moduleID, err = mgr.RegisterModule(modulePath, "")
			if err != nil {
				handleError(fmt.Errorf("failed to register module: %w", err))
				return
			}
		} else if moduleID == "" {
			// Neither path nor ID provided - try to auto-detect
			probed := manager.ProbeModulesWithNames()
			if len(probed) == 0 {
				handleError(fmt.Errorf("no PKCS#11 modules found; specify --module or --module-id"))
				return
			}
			// Use the first probed module
			var err error
			moduleID, err = mgr.RegisterModule(probed[0].LibraryPath, probed[0].DisplayName)
			if err != nil {
				handleError(fmt.Errorf("failed to register module: %w", err))
				return
			}
			printVerbose("Using auto-detected module: %s", moduleID)
		}

		printVerbose("Initializing token on module %s, slot %d", moduleID, slotID)

		err := mgr.InitializeToken(moduleID, slotID, label, soPin, userPin)
		if err != nil {
			handleError(fmt.Errorf("failed to initialize token: %w", err))
			return
		}

		result := map[string]interface{}{
			"module_id": moduleID,
			"slot_id":   slotID,
			"label":     label,
			"status":    "initialized",
		}

		if cfg.OutputFormat == "json" {
			_ = printer.PrintJSON(result)
		} else {
			fmt.Printf("Token initialized successfully\n")
			fmt.Printf("  Module:  %s\n", moduleID)
			fmt.Printf("  Slot:    %d\n", slotID)
			fmt.Printf("  Label:   %s\n", label)
		}
	},
}

// pkcs11ConnectCmd connects to a PKCS#11 token.
var pkcs11ConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to a PKCS#11 token",
	Long:  "Open a session and login to a PKCS#11 token.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		modulePath, _ := cmd.Flags().GetString("module")
		moduleID, _ := cmd.Flags().GetString("module-id")
		slotID, _ := cmd.Flags().GetUint("slot")
		pin, _ := cmd.Flags().GetString("pin")

		if pin == "" {
			handleError(fmt.Errorf("--pin is required"))
			return
		}

		mgr := manager.New()
		defer func() { _ = mgr.Close() }()

		// Register module if path provided
		if modulePath != "" {
			var err error
			moduleID, err = mgr.RegisterModule(modulePath, "")
			if err != nil {
				handleError(fmt.Errorf("failed to register module: %w", err))
				return
			}
		} else if moduleID == "" {
			handleError(fmt.Errorf("--module or --module-id is required"))
			return
		}

		printVerbose("Connecting to module %s, slot %d", moduleID, slotID)

		backend, err := mgr.Connect(moduleID, slotID, pin, "")
		if err != nil {
			handleError(fmt.Errorf("failed to connect: %w", err))
			return
		}

		caps := backend.Capabilities()

		result := map[string]interface{}{
			"module_id":       moduleID,
			"slot_id":         slotID,
			"status":          "connected",
			"backend_type":    string(backend.Type()),
			"hardware_backed": caps.HardwareBacked,
			"security_level":  uint8(caps.SecurityLevel),
		}

		if cfg.OutputFormat == "json" {
			_ = printer.PrintJSON(result)
		} else {
			fmt.Printf("Connected to token\n")
			fmt.Printf("  Module:         %s\n", moduleID)
			fmt.Printf("  Slot:           %d\n", slotID)
			fmt.Printf("  Backend:        %s\n", backend.Type())
			fmt.Printf("  Security Level: %s\n", caps.SecurityLevel.String())
		}
	},
}

// pkcs11DisconnectCmd disconnects from a PKCS#11 token.
var pkcs11DisconnectCmd = &cobra.Command{
	Use:   "disconnect",
	Short: "Disconnect from a PKCS#11 token",
	Long:  "Close the session with a PKCS#11 token.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		moduleID, _ := cmd.Flags().GetString("module-id")
		slotID, _ := cmd.Flags().GetUint("slot")

		if moduleID == "" {
			handleError(fmt.Errorf("--module-id is required"))
			return
		}

		mgr := manager.New()
		defer func() { _ = mgr.Close() }()

		printVerbose("Disconnecting from module %s, slot %d", moduleID, slotID)

		err := mgr.Disconnect(moduleID, slotID)
		if err != nil {
			handleError(fmt.Errorf("failed to disconnect: %w", err))
			return
		}

		result := map[string]interface{}{
			"module_id": moduleID,
			"slot_id":   slotID,
			"status":    "disconnected",
		}

		if cfg.OutputFormat == "json" {
			_ = printer.PrintJSON(result)
		} else {
			fmt.Printf("Disconnected from token\n")
			fmt.Printf("  Module: %s\n", moduleID)
			fmt.Printf("  Slot:   %d\n", slotID)
		}
	},
}

func init() {
	// Register subcommand
	pkcs11RegisterCmd.Flags().String("module", "", "path to PKCS#11 shared library")
	pkcs11RegisterCmd.Flags().String("name", "", "display name for the module")

	// Init token subcommand
	pkcs11InitTokenCmd.Flags().String("module", "", "path to PKCS#11 shared library")
	pkcs11InitTokenCmd.Flags().String("module-id", "", "module ID (alternative to --module)")
	pkcs11InitTokenCmd.Flags().Uint("slot", 0, "slot ID")
	pkcs11InitTokenCmd.Flags().String("label", "", "token label (required)")
	pkcs11InitTokenCmd.Flags().String("so-pin", "", "security officer PIN (required)")
	pkcs11InitTokenCmd.Flags().String("user-pin", "", "user PIN (required)")

	// Connect subcommand
	pkcs11ConnectCmd.Flags().String("module", "", "path to PKCS#11 shared library")
	pkcs11ConnectCmd.Flags().String("module-id", "", "module ID (alternative to --module)")
	pkcs11ConnectCmd.Flags().Uint("slot", 0, "slot ID")
	pkcs11ConnectCmd.Flags().String("pin", "", "user PIN (required)")

	// Disconnect subcommand
	pkcs11DisconnectCmd.Flags().String("module-id", "", "module ID (required)")
	pkcs11DisconnectCmd.Flags().Uint("slot", 0, "slot ID")

	// Add subcommands to pkcs11 parent
	pkcs11Cmd.AddCommand(pkcs11ProbeCmd)
	pkcs11Cmd.AddCommand(pkcs11RegisterCmd)
	pkcs11Cmd.AddCommand(pkcs11ListModulesCmd)
	pkcs11Cmd.AddCommand(pkcs11ListTokensCmd)
	pkcs11Cmd.AddCommand(pkcs11InitTokenCmd)
	pkcs11Cmd.AddCommand(pkcs11ConnectCmd)
	pkcs11Cmd.AddCommand(pkcs11DisconnectCmd)
}
