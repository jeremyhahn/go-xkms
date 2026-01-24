// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"
)

var (
	// Version information (set during build via ldflags).
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Exit codes for the vfido2 command.
const (
	exitSuccess = 0
	exitError   = 1
)

func main() {
	os.Exit(run())
}

// run executes the main application logic and returns an exit code.
// This separation enables easier testing of the main logic.
func run() int {
	cfg := DefaultConfig()

	// Define flags for storage configuration
	var storageType string
	flag.StringVar(&storageType, "storage", string(StorageTypeMemory), "Storage type: memory or file")
	flag.StringVar(&cfg.StoragePath, "storage-path", "/var/lib/vfido2", "Path for file storage")

	// Define flags for device configuration
	flag.StringVar(&cfg.DeviceName, "name", DefaultDeviceName, "Device name")
	flag.StringVar(&cfg.SerialNumber, "serial", "", "Device serial number (auto-generated if empty)")

	// Define flags for PIN configuration
	flag.BoolVar(&cfg.EnablePIN, "pin", false, "Enable PIN support")
	var setPin string
	flag.StringVar(&setPin, "set-pin", "", "Set initial PIN (requires --pin)")

	// Define flags for daemon configuration
	flag.BoolVar(&cfg.Daemon, "daemon", false, "Run as daemon (background)")
	flag.BoolVar(&cfg.Daemon, "d", false, "Run as daemon (short)")
	flag.StringVar(&cfg.PIDFile, "pid-file", DefaultPIDFile, "PID file path")

	// Define flags for logging configuration
	flag.StringVar(&cfg.LogLevel, "log-level", DefaultLogLevel, "Log level: debug, info, warn, error")
	flag.StringVar(&cfg.LogFile, "log-file", "", "Log file path (empty = stdout)")

	// Define flags for user presence mode
	flag.BoolVar(&cfg.Interactive, "interactive", false, "Enable interactive mode (prompt for touch/PIN)")
	var upTimeout string
	flag.StringVar(&upTimeout, "up-timeout", "30s", "Timeout for user presence requests")

	// Define flags for key backend
	flag.StringVar(&cfg.Backend, "backend", "software", "Key backend: software or tpm2")
	flag.StringVar(&cfg.TPMDevice, "tpm-device", "/dev/tpmrm0", "TPM device path (when backend=tpm2)")
	flag.StringVar(&cfg.AttestationFormat, "attestation", "none", "Attestation format: none, packed, or tpm")

	// Define version flag
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.BoolVar(&showVersion, "v", false, "Show version (short)")

	flag.Parse()

	// Handle version display
	if showVersion {
		printVersion()
		return exitSuccess
	}

	// Convert storage type string to StorageType
	cfg.StorageType = StorageType(storageType)

	// Handle PIN configuration
	if setPin != "" {
		if !cfg.EnablePIN {
			fmt.Fprintf(os.Stderr, "Error: --set-pin requires --pin to be enabled\n")
			return exitError
		}
		cfg.PIN = setPin
	}

	// Parse user presence timeout
	if upTimeout != "" {
		timeout, err := time.ParseDuration(upTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid user presence timeout: %v\n", err)
			return exitError
		}
		cfg.UserPresenceTimeout = timeout
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		return exitError
	}

	// Generate serial number if not provided
	if cfg.SerialNumber == "" {
		cfg.SerialNumber = GenerateSerialNumber()
	}

	// Setup logger
	logger, err := setupLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup logger: %v\n", err)
		return exitError
	}

	// Log startup information
	logger.Info("Starting virtual FIDO2 device",
		slog.String("version", version),
		slog.String("name", cfg.DeviceName),
		slog.String("serial", cfg.SerialNumber),
		slog.String("storage", string(cfg.StorageType)),
		slog.Bool("pin_enabled", cfg.EnablePIN),
		slog.Bool("daemon", cfg.Daemon),
		slog.Bool("interactive", cfg.Interactive),
		slog.String("backend", cfg.Backend),
		slog.String("attestation", cfg.AttestationFormat),
	)

	// Write PID file if running as daemon
	if cfg.Daemon {
		if err := writePIDFile(cfg.PIDFile); err != nil {
			logger.Error("Failed to write PID file",
				slog.String("path", cfg.PIDFile),
				slog.Any("error", err),
			)
			return exitError
		}
		defer removePIDFile(cfg.PIDFile, logger)
		logger.Info("PID file created", slog.String("path", cfg.PIDFile))
	}

	// Setup signal handler for graceful shutdown
	ctx, cancel := setupSignalHandler(logger)
	defer cancel()

	// Create the virtual FIDO2 device
	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		logger.Error("Failed to create virtual FIDO2 device",
			slog.Any("error", err),
		)
		return exitError
	}

	// Run the device event loop (blocking)
	if err := device.Run(ctx); err != nil {
		// Context cancellation is expected on shutdown
		if ctx.Err() != nil {
			logger.Info("Device stopped due to shutdown signal")
		} else {
			logger.Error("Device error",
				slog.Any("error", err),
			)
			_ = device.Close()
			return exitError
		}
	}

	// Clean shutdown
	if err := device.Close(); err != nil {
		logger.Error("Error during device cleanup",
			slog.Any("error", err),
		)
		return exitError
	}

	logger.Info("Virtual FIDO2 device stopped")
	return exitSuccess
}

// printVersion prints version information to stdout.
func printVersion() {
	fmt.Printf("vfido2 - Virtual FIDO2 Key (go-keychain)\n")
	fmt.Printf("  Version:    %s\n", version)
	fmt.Printf("  Git Commit: %s\n", commit)
	fmt.Printf("  Built:      %s\n", date)
}
