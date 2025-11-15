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

// Package rest provides a REST API server for the go-keychain library.
//
// The REST API exposes KeyStore functionality over HTTP, allowing remote clients
// to perform key management operations including generation, signing, verification,
// and deletion of cryptographic keys.
//
// # Server Setup
//
// Create a REST server by providing a configuration with one or more KeyStore backends:
//
//	import (
//	    "github.com/jeremyhahn/go-keychain/internal/rest"
//	    "github.com/jeremyhahn/go-keychain/pkg/keychain"
//	    "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
//	    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
//	)
//
//	// Create backend
//	keyStorage, _ := file.NewKeyStorage("/var/lib/keys")
//	certStorage, _ := file.NewCertStorage("/var/lib/certs")
//	backend, _ := pkcs8.NewBackend(&pkcs8.Config{KeyStorage: keyStorage})
//
//	// Create keystore
//	ks, _ := keychain.New(&keychain.Config{
//	    Backend:     backend,
//	    CertStorage: certStorage,
//	})
//
//	// Create REST server
//	server, _ := rest.NewServer(&rest.Config{
//	    Port:     8443,
//	    Backends: map[string]keychain.KeyStore{"pkcs8": ks},
//	    Version:  "1.0.0",
//	})
//
//	// Start server
//	go server.Start()
//
//	// Graceful shutdown
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	server.Stop(ctx)
//
// # API Endpoints
//
// Health Check:
//   - GET /health - Returns server health status
//
// Backend Management:
//   - GET /api/v1/backends - List available backends
//   - GET /api/v1/backends/{id} - Get backend details
//
// Key Management:
//   - POST /api/v1/keys - Generate a new key
//   - GET /api/v1/keys?backend=pkcs8 - List keys in a backend
//   - GET /api/v1/keys/{id}?backend=pkcs8 - Get key details
//   - DELETE /api/v1/keys/{id}?backend=pkcs8 - Delete a key
//
// Cryptographic Operations:
//   - POST /api/v1/keys/{id}/sign?backend=pkcs8 - Sign data with a key
//   - POST /api/v1/keys/{id}/verify?backend=pkcs8 - Verify a signature
//   - POST /api/v1/keys/{id}/rotate?backend=pkcs8 - Rotate a key (replace with new key)
//   - POST /api/v1/keys/{id}/decrypt?backend=pkcs8 - Decrypt data with a key
//
// Certificate Management:
//   - POST /api/v1/certs?key_id=my-key&backend=pkcs8 - Save a certificate
//   - GET /api/v1/certs?backend=pkcs8 - List all certificates
//   - GET /api/v1/certs/{id}?backend=pkcs8 - Get a certificate
//   - DELETE /api/v1/certs/{id}?backend=pkcs8 - Delete a certificate
//   - HEAD /api/v1/certs/{id}?backend=pkcs8 - Check if certificate exists
//   - POST /api/v1/certs/{id}/chain?backend=pkcs8 - Save certificate chain
//   - GET /api/v1/certs/{id}/chain?backend=pkcs8 - Get certificate chain
//
// TLS Helper:
//   - GET /api/v1/tls/{id}?backend=pkcs8 - Get TLS certificate (key+cert+chain)
//
// # Request/Response Format
//
// All requests and responses use JSON format with Content-Type: application/json.
//
// Example key generation request:
//
//	POST /api/v1/keys
//	{
//	  "key_id": "my-rsa-key",
//	  "backend": "pkcs8",
//	  "key_type": "rsa",
//	  "key_size": 2048,
//	  "hash": "SHA256"
//	}
//
// Example signing request:
//
//	POST /api/v1/keys/my-rsa-key/sign?backend=pkcs8
//	{
//	  "data": [116, 101, 115, 116],
//	  "hash": "SHA256"
//	}
//
// Example key rotation request:
//
//	POST /api/v1/keys/my-rsa-key/rotate?backend=pkcs8
//
// Example decryption request:
//
//	POST /api/v1/keys/my-rsa-key/decrypt?backend=pkcs8
//	{
//	  "ciphertext": [99, 105, 112, 104, 101, 114, 116, 101, 120, 116]
//	}
//
// Example certificate save request:
//
//	POST /api/v1/certs?key_id=my-rsa-key&backend=pkcs8
//	{
//	  "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
//	}
//
// Example certificate chain save request:
//
//	POST /api/v1/certs/my-rsa-key/chain?backend=pkcs8
//	{
//	  "cert_chain_pem": [
//	    "-----BEGIN CERTIFICATE-----\n...",
//	    "-----BEGIN CERTIFICATE-----\n..."
//	  ]
//	}
//
// # Error Handling
//
// The server returns standard HTTP status codes:
//   - 200 OK - Request successful
//   - 201 Created - Resource created successfully
//   - 400 Bad Request - Invalid request parameters
//   - 404 Not Found - Resource not found
//   - 409 Conflict - Resource already exists
//   - 500 Internal Server Error - Server error
//
// Error responses include a JSON body with error details:
//
//	{
//	  "error": "key not found",
//	  "message": "Key with ID 'my-key' does not exist",
//	  "code": 404
//	}
//
// # Middleware
//
// The server includes the following middleware:
//   - Recovery - Recovers from panics and returns 500 errors
//   - Logging - Logs all HTTP requests with timing
//   - CORS - Adds CORS headers for cross-origin requests
//   - Content-Type - Ensures JSON content type for responses
//
// # Security Considerations
//
// The REST API currently does not include authentication or TLS encryption.
// For production use, consider:
//   - Running behind a reverse proxy with TLS termination
//   - Implementing authentication middleware (JWT, OAuth, etc.)
//   - Using API keys or mTLS for client authentication
//   - Rate limiting to prevent abuse
//   - Input validation and sanitization
package rest
