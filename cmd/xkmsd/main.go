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

	"github.com/jeremyhahn/go-enclave"
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

// subcommands maps subcommand names to their handler functions. A handler
// reports its exit code as a return value rather than calling os.Exit
// directly, so it can be called from a test in this binary without
// terminating it; only main (via runProcess) turns the returned code into a
// process exit.
var subcommands = map[string]func([]string) int{
	"init": runInit,
}

func main() {
	// runProcess reports the process exit code instead of calling os.Exit
	// directly, so the deferred secure.Purge inside it always runs — an
	// os.Exit inside a function that owns a pending defer skips it.
	os.Exit(runProcess())
}

// runProcess wires the process-owned protected-memory lifecycle around run:
// the interrupt handler that purges mlocked memory before exit, and the
// teardown that runs once run has returned.
//
// secure.Purge (go-qrdb's memguard-backed Secret/Buffer) and enclave.WipeAll
// (go-xkms's own go-enclave-backed MemoryEnclaves -- pintpm2's cached FIDO2
// hash, sealed backend DEKs) are two distinct protected-memory subsystems
// with no shared lifecycle hook, so the binary that owns process exit calls
// both. Libraries in this repo call neither: WipeAll is a process-wide
// teardown that belongs only to the binary (go-xkms#623), and specifically
// to the one call that owns the real process's exit -- not to run, which
// tests also call directly to reach its flag-parsing and dispatch branches.
// A WipeAll wired into run instead destroyed every MemoryEnclave live
// anywhere in the test binary each time one of those tests called it,
// including sealers other tests in the same package were still using
// (go-xkms#1153).
func runProcess() int {
	// Wire the process signal handler so SIGINT/SIGTERM purge all
	// mlocked memory before exit, and arrange for a graceful Purge on
	// any orderly shutdown path. Mirrors the qrdbd pattern exactly.
	// See pkg/secure/interrupt.go in go-qrdb.
	secure.CatchInterrupt()
	defer func() {
		if err := secure.Purge(); err != nil {
			fmt.Fprintf(os.Stderr, "xkmsd: secure.Purge: %v\n", err)
		}
		if count, err := enclave.WipeAll(); err != nil {
			fmt.Fprintf(os.Stderr, "xkmsd: enclave.WipeAll: %d still held, %v\n", count, err)
		}
	}()

	return run()
}

// run resolves flags and configuration, and either dispatches a subcommand
// or starts and serves the daemon until shutdown. It performs no process-wide
// teardown of its own -- that is runProcess's job -- so it is safe for tests
// to call directly, including more than once in the same test binary.
func run() int {
	// Check for subcommands before parsing global flags.
	if len(os.Args) > 1 {
		if handler, ok := subcommands[os.Args[1]]; ok {
			return handler(os.Args[2:])
		}
	}

	// Parse command-line flags
	configPath := flag.String("config", "/etc/xkms/xkmsd.yaml", "Path to configuration file")
	configShort := flag.String("c", "", "Path to configuration file (short)")
	daemonMode := flag.Bool("daemon", false, "Run as daemon")
	daemonShort := flag.Bool("d", false, "Run as daemon (short)")
	pidFile := flag.String("pid-file", "", "Path to PID file")
	showVersion := flag.Bool("version", false, "Show version information")
	srvFlags := registerServerFlags(flag.CommandLine)
	flag.Parse()

	// Handle short flag aliases
	if *configShort != "" {
		*configPath = *configShort
	}
	if *daemonShort {
		*daemonMode = true
	}

	// Show version if requested.
	if *showVersion {
		fmt.Printf("xkmsd - xKMS Daemon\n")
		fmt.Printf("  Version:    %s\n", version)
		fmt.Printf("  Git Commit: %s\n", commit)
		fmt.Printf("  Built:      %s\n", date)
		return 0
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
		return 1
	}

	// Flags are the top of the precedence order (flags > env > file >
	// defaults): config.Load resolved the lower three, and only a flag the
	// operator actually set is written over that result.
	srvFlags.apply(cfg, flag.CommandLine)

	logger.Info("Configuration loaded successfully",
		slog.Any("backends", cfg.GetEnabledBackends()),
		slog.String("default_backend", string(cfg.Default)),
		slog.String("host", cfg.Server.Host))

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
		return 1
	}

	// Write PID file if specified
	if *pidFile != "" {
		if err := writePIDFile(*pidFile); err != nil {
			logger.Error("Failed to write PID file", slog.Any("error", err))
			return 1
		}
		defer removePIDFile(*pidFile, logger)
	}

	// Build the ACME admin ServiceModule ahead of server.New: module
	// registration happens during embedded qrdb node construction (inside
	// New itself), before the admin service, its ACME CA/storage, or the
	// node's TenantService exist. Its router resolver stays nil (every
	// admin route answers 503) until finalizeAdminModule publishes the
	// assembled router below, after both srv and the ACME subsystem are up.
	adminModule, err := newAdminModule()
	if err != nil {
		logger.Error("Failed to construct admin ServiceModule", slog.Any("error", err))
		return 1
	}

	// Create server
	srv, err := server.New(cfg, server.WithExtraModules(adminModule))
	if err != nil {
		logger.Error("Failed to create server", slog.Any("error", err))
		return 1
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
			if err := reloadConfiguration(srv, *configPath, srvFlags, flag.CommandLine, logger); err != nil {
				logger.Error("Failed to reload configuration", slog.Any("error", err))
			} else {
				logger.Info("Configuration reloaded successfully")
			}
		}
	}()

	return serve(shutdownCtx, srv, cfg, logger)
}

// serve starts srv (and its optional ACME companion) and blocks until
// shutdownCtx is done, then drains both gracefully. It is the part of run()
// the go-xkms#1141 split names explicitly: "from srv.Start() through the
// shutdown calls". srv is already fully constructed (server.New, including
// the admin ServiceModule registered via WithExtraModules, and any UI
// assets) by the time serve is called; serve owns none of run()'s
// process-wide setup (signal wiring, PID file, config reload) and performs
// no teardown of its own beyond srv's and its ACME companion's -- so it is
// safe for a test to call directly with a shutdownCtx it controls (for
// example context.WithCancel, canceled once the test has observed the
// server is up) instead of a real SIGTERM/SIGINT delivered to the process.
func serve(shutdownCtx context.Context, srv *server.Server, cfg *config.Config, logger *slog.Logger) int {
	// Start the server
	if err := srv.Start(); err != nil {
		logger.Error("Failed to start server", slog.Any("error", err))
		return 1
	}

	// Start the optional ACME server. When acme.enabled is false this is a
	// no-op and returns (nil, nil).
	acme, err := startACMEServer(srv, cfg, logger)
	if err != nil {
		logger.Error("Failed to start ACME server", slog.Any("error", err))
		if shutdownErr := srv.Shutdown(); shutdownErr != nil {
			logger.Error("Error during shutdown after ACME failure", slog.Any("error", shutdownErr))
		}
		return 1
	}

	// Publish the admin surface's router now that both srv and the ACME
	// subsystem (or its absence, when acme.enabled is false) are settled.
	if err := finalizeAdminModule(srv, acme, logger); err != nil {
		logger.Error("Failed to finalize admin ServiceModule", slog.Any("error", err))
		if shutdownErr := srv.Shutdown(); shutdownErr != nil {
			logger.Error("Error during shutdown after admin module failure", slog.Any("error", shutdownErr))
		}
		return 1
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
		return 1
	}

	logger.Info("Server stopped successfully")
	return 0
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

// resolveReloadConfig loads the configuration for a reload exactly as start-up
// resolves it: config.Load settles defaults, file and environment, then the
// flags the operator set on the command line are written over the result.
// Without the second step a SIGHUP silently dropped every flag -- a daemon
// started as `xkmsd --host 10.0.0.5` re-resolved server.host from the file
// and, on its next planned restart, bound every interface.
func resolveReloadConfig(configPath string, flags *serverFlags, fs *flag.FlagSet) (*config.Config, error) {
	newCfg, err := config.Load(configPath)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrConfigLoad, Err: err}
	}
	flags.apply(newCfg, fs)
	return newCfg, nil
}

// reloadConfiguration attempts to reload the server configuration. It
// resolves the new configuration through the same layers as start-up (flags
// included) and re-applies the secure-by-default gate so a SIGHUP cannot
// quietly drop the daemon to a non-compliant posture (no encryption-at-rest /
// TLS / authentication / CA). The refusal is unconditional, mirroring startup.
func reloadConfiguration(srv *server.Server, configPath string, flags *serverFlags, fs *flag.FlagSet, logger *slog.Logger) error {
	newCfg, err := resolveReloadConfig(configPath, flags, fs)
	if err != nil {
		return err
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
		slog.String("default_backend", string(newCfg.Default)),
		slog.String("host", newCfg.Server.Host))

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
