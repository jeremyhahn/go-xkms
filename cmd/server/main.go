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
	configPath := flag.String("config", "/etc/keychain/config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	// Show version if requested
	if *showVersion {
		fmt.Printf("go-keychain server\n")
		fmt.Printf("  Version:    %s\n", version)
		fmt.Printf("  Git Commit: %s\n", commit)
		fmt.Printf("  Built:      %s\n", date)
		os.Exit(0)
	}

	// Check for config file override via environment
	if envConfig := os.Getenv("KEYSTORE_CONFIG"); envConfig != "" {
		*configPath = envConfig
	}

	slog.Info("Starting keychain server",
		"config", *configPath,
		"version", version)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("Failed to load configuration", slog.Any("error", err))
		os.Exit(1)
	}

	slog.Info("Configuration loaded successfully",
		"backends", cfg.GetEnabledBackends(),
		"default_backend", string(cfg.Default))

	// Create server
	srv, err := server.New(cfg)
	if err != nil {
		slog.Error("Failed to create server", slog.Any("error", err))
		os.Exit(1)
	}

	// Setup signal handler for graceful shutdown
	shutdownCtx := server.SetupSignalHandler()

	// Start the server
	if err := srv.Start(); err != nil {
		slog.Error("Failed to start server", slog.Any("error", err))
		os.Exit(1)
	}

	// Wait for shutdown signal
	<-shutdownCtx.Done()

	// Gracefully shutdown
	if err := srv.Shutdown(); err != nil {
		slog.Error("Error during shutdown", slog.Any("error", err))
		os.Exit(1)
	}

	slog.Info("Server stopped successfully")
}
