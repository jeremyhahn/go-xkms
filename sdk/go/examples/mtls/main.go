// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Example demonstrating mTLS (mutual TLS) configuration with the SDK.

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jeremyhahn/go-xkms/sdk/go"
)

func main() {
	ctx := context.Background()

	// mTLS configuration
	// In production, these paths would point to real certificates
	cfg := &xkms.BackendConfig{
		Protocol:    xkms.ProtocolREST,
		Address:     "https://localhost:8443",
		TLSEnabled:  true,
		TLSCAFile:   "/path/to/ca.pem",     // CA certificate
		TLSCertFile: "/path/to/client.pem", // Client certificate
		TLSKeyFile:  "/path/to/client-key.pem",
	}

	// Create client with mTLS configuration
	client, err := xkms.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("Failed to close client: %v", err)
		}
	}()

	// Connect with mTLS
	if err := client.Connect(ctx); err != nil {
		log.Printf("Connection failed (expected in this example): %v", err)
		fmt.Println("\nThis example demonstrates mTLS configuration.")
		fmt.Println("In production, configure the paths to actual certificates.")
		return
	}

	// Check server health
	health, err := client.Health(ctx)
	if err != nil {
		log.Fatalf("Failed to check health: %v", err)
	}
	fmt.Printf("Server status: %s (version: %s)\n", health.Status, health.Version)

	// Continue with secure operations...
	fmt.Println("Connected with mTLS successfully!")
}
