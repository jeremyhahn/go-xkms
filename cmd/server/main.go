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
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/jeremyhahn/go-keychain/internal/config"
	"github.com/jeremyhahn/go-keychain/internal/server"
)

var (
	// Version information (set during build)
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "/etc/keychain/keychaind.yaml", "Path to configuration file")
	configShort := flag.String("c", "", "Path to configuration file (short)")
	daemonMode := flag.Bool("daemon", false, "Run as daemon")
	daemonShort := flag.Bool("d", false, "Run as daemon (short)")
	pidFile := flag.String("pid-file", "", "Path to PID file")
	showVersion := flag.Bool("version", false, "Show version information")
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
		fmt.Printf("keychaind - Keychain Daemon\n")
		fmt.Printf("  Version:    %s\n", version)
		fmt.Printf("  Git Commit: %s\n", commit)
		fmt.Printf("  Built:      %s\n", date)
		os.Exit(0)
	}

	// Check for config file override via environment
	if envConfig := os.Getenv("KEYCHAIN_CONFIG"); envConfig != "" {
		*configPath = envConfig
	}

	// Setup initial logging (will be reconfigured after loading config)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	logger.Info("Starting keychain daemon",
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

	// Wait for shutdown signal
	<-shutdownCtx.Done()

	logger.Info("Shutting down server...")

	// Gracefully shutdown
	if err := srv.Shutdown(); err != nil {
		logger.Error("Error during shutdown", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("Server stopped successfully")
}

// setupSignalHandler sets up signal handling for graceful shutdown and config reload
func setupSignalHandler(logger *slog.Logger) (context.Context, chan os.Signal) {
	ctx, cancel := context.WithCancel(context.Background())

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

// reloadConfiguration attempts to reload the server configuration
func reloadConfiguration(srv *server.Server, configPath string, logger *slog.Logger) error {
	// Load new configuration
	newCfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Validate new configuration
	if err := newCfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Attempt to reload the server with new configuration
	if err := srv.Reload(newCfg); err != nil {
		return fmt.Errorf("failed to apply configuration: %w", err)
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
		return fmt.Errorf("failed to create PID file directory: %w", err)
	}

	// Write PID to file
	pid := os.Getpid()
	content := []byte(strconv.Itoa(pid) + "\n")

	// #nosec G306 - PID file should be readable by all
	if err := os.WriteFile(path, content, 0644); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	return nil
}

// removePIDFile removes the PID file
func removePIDFile(path string, logger *slog.Logger) {
	if err := os.Remove(path); err != nil {
		logger.Warn("Failed to remove PID file", slog.Any("error", err))
	}
}
