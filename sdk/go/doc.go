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

// Package keychain provides a unified Go SDK for interacting with the go-keychain
// Key Management System. It supports multiple communication protocols and provides
// 100% coverage of the KeychainService API.
//
// # Supported Protocols
//
// The SDK supports the following communication protocols:
//
//   - Unix domain socket (default): Fastest option for local communication
//   - gRPC: High-performance RPC with protocol buffers
//   - REST: HTTP/HTTPS for maximum compatibility
//   - QUIC: HTTP/3 over QUIC for modern networks
//   - MCP: JSON-RPC 2.0 over TCP (Model Context Protocol for AI agents)
//   - Embedded: Direct in-process calls (no network overhead)
//
// # Quick Start
//
// Create a client using the default Unix socket protocol:
//
//	client, err := keychain.New(nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	if err := client.Connect(context.Background()); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Generate a key
//	resp, err := client.GenerateKey(ctx, &keychain.GenerateKeyRequest{
//	    KeyID:   "my-key",
//	    Backend: "software",
//	    KeyType: "EC",
//	    Curve:   "P-256",
//	})
//
// # Protocol Selection
//
// To use a specific protocol:
//
//	// REST API
//	client, _ := keychain.New(&keychain.Config{
//	    Protocol: keychain.ProtocolREST,
//	    Address:  "https://localhost:8443",
//	})
//
//	// gRPC
//	client, _ := keychain.New(&keychain.Config{
//	    Protocol: keychain.ProtocolGRPC,
//	    Address:  "localhost:9443",
//	})
//
//	// QUIC
//	client, _ := keychain.New(&keychain.Config{
//	    Protocol: keychain.ProtocolQUIC,
//	    Address:  "localhost:8444",
//	})
//
//	// MCP (JSON-RPC)
//	client, _ := keychain.New(&keychain.Config{
//	    Protocol: keychain.ProtocolMCP,
//	    Address:  "localhost:9444",
//	})
//
// # URL-based Configuration
//
// You can also create clients from URLs:
//
//	client, _ := keychain.NewFromURL("https://localhost:8443")  // REST
//	client, _ := keychain.NewFromURL("grpc://localhost:9443")   // gRPC
//	client, _ := keychain.NewFromURL("quic://localhost:8444")   // QUIC
//	client, _ := keychain.NewFromURL("mcp://localhost:9444")    // MCP (JSON-RPC)
//	client, _ := keychain.NewFromURL("unix:///path/to/socket")  // Unix socket
//
// # Embedded Mode
//
// For in-process usage without network overhead:
//
//	service := keychain.NewKeychainService(...)
//	client, _ := keychain.NewEmbedded(service)
//
// # Supported Backends
//
// The SDK supports all go-keychain backends:
//
//   - software: PKCS#8 file-based keys
//   - pkcs11: HSM/Smart card via PKCS#11
//   - tpm2: TPM 2.0 module
//   - awskms: AWS Key Management Service
//   - gcpkms: Google Cloud KMS
//   - azurekv: Azure Key Vault
//   - vault: HashiCorp Vault
//   - quantum: Post-quantum cryptography (ML-DSA, ML-KEM)
//   - threshold: Threshold cryptography
//   - frost: FROST threshold signatures (RFC 9591)
//
// # TLS Configuration
//
// For secure connections with TLS:
//
//	client, _ := keychain.New(&keychain.Config{
//	    Protocol:              keychain.ProtocolREST,
//	    Address:               "https://localhost:8443",
//	    TLSEnabled:            true,
//	    TLSCAFile:             "/path/to/ca.pem",
//	    TLSCertFile:           "/path/to/client.pem",  // mTLS
//	    TLSKeyFile:            "/path/to/client-key.pem",
//	})
//
// # Error Handling
//
// The SDK defines typed errors for common failure cases:
//
//   - ErrNotConnected: Client is not connected to server
//   - ErrConnectionFailed: Connection attempt failed
//   - ErrUnsupportedProtocol: Protocol not supported
//   - ErrNilService: Nil service passed to NewEmbedded
//   - ErrKeyNotFound: Requested key does not exist
//   - ErrCertificateNotFound: Requested certificate does not exist
//   - ErrBackendNotFound: Requested backend does not exist
package keychain
