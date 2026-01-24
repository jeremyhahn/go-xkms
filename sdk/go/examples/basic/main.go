// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Basic example demonstrating SDK usage with the default Unix socket protocol.

package main

import (
	"context"
	"fmt"
	"log"

	keychain "github.com/jeremyhahn/go-keychain/sdk/go"
)

func main() {
	ctx := context.Background()

	// Create a client with default Unix socket configuration
	client, err := keychain.New(nil)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("Failed to close client: %v", err)
		}
	}()

	// Connect to the server
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	// Check server health
	health, err := client.Health(ctx)
	if err != nil {
		log.Fatalf("Failed to check health: %v", err)
	}
	fmt.Printf("Server status: %s (version: %s)\n", health.Status, health.Version)

	// List available backends
	backends, err := client.ListBackends(ctx)
	if err != nil {
		log.Fatalf("Failed to list backends: %v", err)
	}
	fmt.Printf("Available backends: %d\n", len(backends.Backends))
	for _, b := range backends.Backends {
		fmt.Printf("  - %s (%s)\n", b.ID, b.Type)
	}

	// Generate an EC key
	keyResp, err := client.GenerateKey(ctx, &keychain.GenerateKeyRequest{
		KeyID:   "example-key",
		Backend: "software",
		KeyType: "EC",
		Curve:   "P-256",
	})
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	fmt.Printf("Generated key: %s (type: %s)\n", keyResp.KeyID, keyResp.KeyType)

	// Sign data
	data := []byte("Hello, go-keychain!")
	signResp, err := client.Sign(ctx, &keychain.SignRequest{
		Backend: "software",
		KeyID:   "example-key",
		Data:    data,
		Hash:    "SHA256",
	})
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	fmt.Printf("Signature: %x...\n", signResp.Signature[:32])

	// Verify signature
	verifyResp, err := client.Verify(ctx, &keychain.VerifyRequest{
		Backend:   "software",
		KeyID:     "example-key",
		Data:      data,
		Signature: signResp.Signature,
		Hash:      "SHA256",
	})
	if err != nil {
		log.Fatalf("Failed to verify: %v", err)
	}
	fmt.Printf("Signature valid: %t\n", verifyResp.Valid)

	// Clean up - delete the key
	_, err = client.DeleteKey(ctx, "software", "example-key")
	if err != nil {
		log.Fatalf("Failed to delete key: %v", err)
	}
	fmt.Println("Key deleted successfully")
}
