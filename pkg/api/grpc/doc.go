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

// Package grpc provides a gRPC server implementation for the go-keychain library.
//
// The gRPC server exposes key management and cryptographic operations through
// a standardized API defined in the keychain.proto file. It supports multiple
// backend providers including software keystores (PKCS#8), hardware security
// modules (PKCS#11), TPM 2.0, and cloud KMS services (AWS, GCP, Azure, Vault).
//
// Features:
//   - Health checking and backend discovery
//   - Key generation for RSA, ECDSA, and Ed25519 algorithms
//   - Key listing and retrieval with pagination
//   - Signing and verification operations
//   - Key deletion with proper error handling
//   - Request logging and panic recovery interceptors
//   - Proper gRPC error codes (InvalidArgument, NotFound, Internal, etc.)
//
// Example usage:
//
//	// Create a backend registry
//	manager := grpc.NewBackendRegistry()
//
//	// Register a PKCS#8 backend
//	keyStorage := file.NewKeyStorage("/var/lib/keys")
//	certStorage := file.NewCertStorage("/var/lib/certs")
//	pkcs8Backend := pkcs8.NewBackend(keyStorage)
//	keystore, _ := keychain.New(&keychain.Config{
//	    Backend:     pkcs8Backend,
//	    CertStorage: certStorage,
//	})
//	manager.Register("pkcs8", keystore)
//
//	// Create and start the gRPC server
//	server, _ := grpc.NewServer(&grpc.ServerConfig{
//	    Port:           9090,
//	    Manager:        manager,
//	    EnableLogging:  true,
//	    EnableRecovery: true,
//	})
//
//	// Start server (blocks until stopped)
//	if err := server.Start(); err != nil {
//	    log.Fatal(err)
//	}
//
// The server listens on the configured port (default: 9090) and handles all
// KeystoreService RPC methods defined in the proto file. All operations are
// validated and proper error codes are returned for invalid requests.
package grpc
