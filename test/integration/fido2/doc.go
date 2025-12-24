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

// Package fido2 provides integration tests for FIDO2/WebAuthn functionality.
//
// These tests verify the complete FIDO2 stack including device enumeration,
// credential enrollment, and authentication using real or virtual FIDO2 security keys.
//
// # Test Coverage
//
//  1. Device Detection - Enumerate and detect FIDO2 authenticators
//  2. Credential Enrollment - Register new FIDO2 credentials
//  3. Authentication - Unlock/authenticate using registered credentials
//  4. CLI Commands - Test all 5 FIDO2 CLI commands across protocols
//  5. Multi-Protocol - Test FIDO2 operations across REST, gRPC, QUIC, MCP, Unix
//  6. WebAuthn Server - Server-side WebAuthn ceremony validation
//
// # Requirements
//
//  - FIDO2-compatible security key (optional, tests skip if not available)
//  - CanoKey QEMU virtual device (optional, via CANOKEY_QEMU env var)
//  - go-keychain server running (for multi-protocol and server tests)
//  - libfido2 or compatible FIDO2 library
//
// # Running Tests
//
//	# Run all FIDO2 integration tests (requires FIDO2 device)
//	go test -v -tags "integration,fido2" ./test/integration/fido2/...
//
//	# Run with CanoKey QEMU virtual device
//	CANOKEY_QEMU=/dev/hidraw0 go test -v -tags "integration,fido2" ./test/integration/fido2/...
//
//	# Run only CLI tests (requires running server)
//	go test -v -tags "integration,fido2" -run TestCLI ./test/integration/fido2/...
//
//	# Run multi-protocol tests
//	go test -v -tags "integration,fido2" -run TestMultiProtocol ./test/integration/fido2/...
//
// # Environment Variables
//
//  - FIDO2_DEVICE_PATH: Specific FIDO2 device path to use
//  - CANOKEY_QEMU: Path to CanoKey QEMU virtual device (e.g., /dev/hidraw0)
//  - FIDO2_PIN: PIN for user verification (if required by device)
//  - KEYSTORE_CLI_BIN: Path to keychain CLI binary
//  - KEYSTORE_REST_URL: REST API server URL
//  - KEYSTORE_GRPC_ADDR: gRPC server address
//  - KEYSTORE_QUIC_URL: QUIC server URL
//  - KEYSTORE_MCP_ADDR: MCP server address
//  - KEYSTORE_UNIX_SOCKET: Unix socket path
//
// # FIDO2 CLI Commands
//
//  1. fido2 list-devices - List available FIDO2 security keys
//  2. fido2 wait-device - Wait for a FIDO2 device to be connected
//  3. fido2 register <username> - Register a new FIDO2 credential
//  4. fido2 authenticate - Authenticate using a FIDO2 credential
//  5. fido2 info - Get information about a connected FIDO2 device
//
// # Test Isolation
//
// Tests are designed to be isolated and can run in parallel when multiple
// FIDO2 devices are available. Each test uses unique credentials and does
// not interfere with other tests or existing device state.
//
//go:build integration && fido2

package fido2
