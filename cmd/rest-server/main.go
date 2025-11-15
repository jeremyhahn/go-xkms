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
	"syscall"
	"time"

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
		fmt.Printf("go-keychain REST server\n")
		fmt.Printf("  Version:    %s\n", version)
		fmt.Printf("  Git Commit: %s\n", commit)
		fmt.Printf("  Built:      %s\n", date)
		os.Exit(0)
	}

	// Check for config file override via environment
	if envConfig := os.Getenv("KEYSTORE_CONFIG"); envConfig != "" {
		*configPath = envConfig
	}

	slog.Info("Starting REST server",
		"config", *configPath,
		"version", version)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("Failed to load configuration", slog.Any("error", err))
		os.Exit(1)
	}

	// Ensure REST protocol is enabled
	if !cfg.Protocols.REST {
		slog.Error("REST protocol is not enabled in configuration")
		os.Exit(1)
	}

	slog.Info("Configuration loaded successfully",
		"backends", cfg.GetEnabledBackends(),
		"default_backend", string(cfg.Default),
		"port", cfg.Server.RESTPort)

	// Create unified server to initialize backends
	srv, err := server.New(cfg)
	if err != nil {
		slog.Error("Failed to create server", slog.Any("error", err))
		os.Exit(1)
	}

	// Get the REST server from the unified server
	restServer := srv.RESTServer()
	if restServer == nil {
		slog.Error("Failed to initialize REST server")
		os.Exit(1)
	}

	// Setup signal handler for graceful shutdown
	shutdownCtx := setupSignalHandler()

	// Start the REST server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := restServer.Start(); err != nil {
			errChan <- err
		}
	}()

	slog.Info("REST server started successfully", "port", cfg.Server.RESTPort)

	// Wait for shutdown signal or error
	select {
	case <-shutdownCtx.Done():
		slog.Info("Shutdown signal received")
	case err := <-errChan:
		slog.Error("Server error", slog.Any("error", err))
	}

	// Gracefully shutdown
	shutdownTimeout, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := restServer.Stop(shutdownTimeout); err != nil {
		slog.Error("Error during REST server shutdown", slog.Any("error", err))
	}

	if err := srv.Shutdown(); err != nil {
		slog.Error("Error during server shutdown", slog.Any("error", err))
		os.Exit(1)
	}

	slog.Info("REST server stopped successfully")
}

// setupSignalHandler sets up signal handling for graceful shutdown
func setupSignalHandler() context.Context {
	ctx, cancel := context.WithCancel(context.Background())

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalCh
		slog.Info("Received shutdown signal")
		cancel()
	}()

	return ctx
}
