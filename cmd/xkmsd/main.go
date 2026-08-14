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
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/server"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/web"
)

var (
	// Version information (set during build)
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// subcommands maps subcommand names to their handler functions.
var subcommands = map[string]func([]string){
	"init": runInit,
}

func main() {
	// Wire the process signal handler so SIGINT/SIGTERM purge all
	// mlocked memory before exit, and arrange for a graceful Purge on
	// any orderly shutdown path. Mirrors the qrdbd pattern exactly.
	// See pkg/secure/interrupt.go in go-qrdb.
	secure.CatchInterrupt()
	defer func() {
		if err := secure.Purge(); err != nil {
			fmt.Fprintf(os.Stderr, "xkmsd: secure.Purge: %v\n", err)
		}
	}()

	// Check for subcommands before parsing global flags.
	if len(os.Args) > 1 {
		if handler, ok := subcommands[os.Args[1]]; ok {
			handler(os.Args[2:])
			return
		}
	}

	// Parse command-line flags
	configPath := flag.String("config", "/etc/xkms/xkmsd.yaml", "Path to configuration file")
	configShort := flag.String("c", "", "Path to configuration file (short)")
	daemonMode := flag.Bool("daemon", false, "Run as daemon")
	daemonShort := flag.Bool("d", false, "Run as daemon (short)")
	pidFile := flag.String("pid-file", "", "Path to PID file")
	showVersion := flag.Bool("version", false, "Show version information")
	sealPassphrase := flag.String("seal-passphrase", "", "Barrier auto-unseal passphrase (prefer XKMS_SEAL_PASSPHRASE env or a credential:// reference; passing a secret on the command line is discouraged)")
	flag.Parse()

	// Handle short flag aliases
	if *configShort != "" {
		*configPath = *configShort
	}
	if *daemonShort {
		*daemonMode = true
	}

	// Show version if requested
	if *showVersion {
		fmt.Printf("xkmsd - xKMS Daemon\n")
		fmt.Printf("  Version:    %s\n", version)
		fmt.Printf("  Git Commit: %s\n", commit)
		fmt.Printf("  Built:      %s\n", date)
		os.Exit(0)
	}

	// Check for config file override via environment
	if envConfig := os.Getenv("XKMS_CONFIG"); envConfig != "" {
		*configPath = envConfig
	}

	// Setup initial logging (will be reconfigured after loading config)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	logger.Info("Starting xkms daemon",
		slog.String("config", *configPath),
		slog.String("version", version),
		slog.Bool("daemon_mode", *daemonMode))

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("Failed to load configuration", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("Configuration loaded successfully",
		slog.Any("backends", cfg.GetEnabledBackends()),
		slog.String("default_backend", string(cfg.Default)))

	// The --seal-passphrase flag takes precedence over XKMS_SEAL_PASSPHRASE and
	// the config file (CLI > env > config), giving an operator an explicit
	// override for the barrier auto-unseal secret.
	if *sealPassphrase != "" {
		cfg.Barrier.Passphrase = *sealPassphrase
	}

	// Secure-by-default gate: refuse to serve a non-compliant configuration
	// (no encryption-at-rest / TLS / authentication / CA). There is no
	// override — the daemon has an embedded CA and mints its own TLS
	// certificate, so a secure deployment needs no manual provisioning and an
	// insecure one has no legitimate reason to exist. Every gap names the
	// exact configuration key to turn on; `xkmsd init` provisions them all.
	// The library stays permissive for embedded/test use.
	if gaps := cfg.ComplianceGaps(); len(gaps) > 0 {
		logger.Error("xkmsd refuses to start with an insecure configuration; "+
			"FedRAMP/PCI-DSS/HIPAA require encryption-at-rest, TLS, authentication, and a CA. "+
			"Run `xkmsd init` to provision a secure deployment, or enable the reported settings.",
			slog.Any("gaps", gaps))
		os.Exit(1)
	}

	// Write PID file if specified
	if *pidFile != "" {
		if err := writePIDFile(*pidFile); err != nil {
			logger.Error("Failed to write PID file", slog.Any("error", err))
			os.Exit(1)
		}
		defer removePIDFile(*pidFile, logger)
	}

	// Create server
	srv, err := server.New(cfg)
	if err != nil {
		logger.Error("Failed to create server", slog.Any("error", err))
		os.Exit(1)
	}

	// Serve the embedded web UI when this binary was built with the "ui"
	// tag (the stub Assets returns ok=false otherwise). The config-level
	// ui.enabled switch is enforced inside the server.
	if assets, ok := web.Assets(); ok {
		srv.SetUIAssets(assets)
		logger.Info("Embedded web UI assets loaded")
	}

	// Setup signal handler for graceful shutdown and config reload
	shutdownCtx, reloadCh := setupSignalHandler(logger)

	// Create a channel to track config reload requests
	configReloadCh := make(chan struct{}, 1)

	// Handle config reload signals in a separate goroutine
	go func() {
		for range reloadCh {
			logger.Info("Received SIGHUP, reloading configuration...")
			configReloadCh <- struct{}{}
		}
	}()

	// Handle config reload
	go func() {
		for range configReloadCh {
			if err := reloadConfiguration(srv, *configPath, logger); err != nil {
				logger.Error("Failed to reload configuration", slog.Any("error", err))
			} else {
				logger.Info("Configuration reloaded successfully")
			}
		}
	}()

	// Start the server
	if err := srv.Start(); err != nil {
		logger.Error("Failed to start server", slog.Any("error", err))
		os.Exit(1)
	}

	// Start the optional ACME server. When acme.enabled is false this is a
	// no-op and returns (nil, nil).
	acme, err := startACMEServer(srv, cfg, logger)
	if err != nil {
		logger.Error("Failed to start ACME server", slog.Any("error", err))
		if shutdownErr := srv.Shutdown(); shutdownErr != nil {
			logger.Error("Error during shutdown after ACME failure", slog.Any("error", shutdownErr))
		}
		os.Exit(1)
	}

	// Wait for shutdown signal
	<-shutdownCtx.Done()

	logger.Info("Shutting down server...")

	// Gracefully shutdown the ACME server first so it stops accepting new
	// requests before the primary backends are torn down.
	acmeShutdownCtx, acmeCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := acme.Shutdown(acmeShutdownCtx); err != nil {
		logger.Error("Error during ACME shutdown", slog.Any("error", err))
	}
	acmeCancel()

	// Gracefully shutdown
	if err := srv.Shutdown(); err != nil {
		logger.Error("Error during shutdown", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("Server stopped successfully")
}

// setupSignalHandler sets up signal handling for graceful shutdown and config reload
func setupSignalHandler(logger *slog.Logger) (context.Context, chan os.Signal) {
	ctx, cancel := context.WithCancel(context.Background()) // #nosec G118 -- cancel is called in the goroutine below

	shutdownCh := make(chan os.Signal, 1)
	reloadCh := make(chan os.Signal, 1)

	// Handle SIGTERM and SIGINT for graceful shutdown
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)

	// Handle SIGHUP for config reload
	signal.Notify(reloadCh, syscall.SIGHUP)

	go func() {
		select {
		case sig := <-shutdownCh:
			logger.Info("Received shutdown signal", slog.String("signal", sig.String()))
			cancel()
		case <-ctx.Done():
			return
		}
	}()

	return ctx, reloadCh
}

// reloadConfiguration attempts to reload the server configuration. It re-applies
// the secure-by-default gate so a SIGHUP cannot quietly drop the daemon to a
// non-compliant posture (no encryption-at-rest / TLS / authentication / CA).
// The refusal is unconditional, mirroring startup.
func reloadConfiguration(srv *server.Server, configPath string, logger *slog.Logger) error {
	// Load new configuration (config.Load validates before returning).
	newCfg, err := config.Load(configPath)
	if err != nil {
		return &WrappedError{Sentinel: ErrConfigLoad, Err: err}
	}

	// Secure-by-default gate, mirrored from startup: never swap in a
	// non-compliant configuration.
	if gaps := newCfg.ComplianceGaps(); len(gaps) > 0 {
		return &InsecureReloadError{Gaps: gaps}
	}

	// Attempt to reload the server with new configuration
	if err := srv.Reload(newCfg); err != nil {
		return &WrappedError{Sentinel: ErrConfigApply, Err: err}
	}

	logger.Info("Configuration reloaded",
		slog.Any("backends", newCfg.GetEnabledBackends()),
		slog.String("default_backend", string(newCfg.Default)))

	return nil
}

// writePIDFile writes the current process ID to a file
func writePIDFile(path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return &WrappedError{Sentinel: ErrPIDDirCreate, Err: err}
	}

	// Write PID to file
	pid := os.Getpid()
	content := []byte(strconv.Itoa(pid) + "\n")

	// #nosec G306 - PID file should be readable by all
	if err := os.WriteFile(path, content, 0644); err != nil {
		return &WrappedError{Sentinel: ErrPIDFileWrite, Err: err}
	}

	return nil
}

// removePIDFile removes the PID file
func removePIDFile(path string, logger *slog.Logger) {
	if err := os.Remove(path); err != nil {
		logger.Warn("Failed to remove PID file", slog.Any("error", err))
	}
}
