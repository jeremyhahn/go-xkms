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

// Package manager provides high-level PKCS#11 multi-token management.
//
// This package manages the lifecycle of PKCS#11 modules and their tokens,
// providing a unified interface for:
//   - Module registration and lifecycle management
//   - Slot and token enumeration
//   - Session management with automatic login
//   - Token initialization and PIN management
//   - Multi-module/multi-token coordination
//
// The package is designed to be used by both CLI tools (xkmsctl) and
// GUI applications (xkey) for consistent PKCS#11 token management.
//
// # Build Tags
//
// This package requires the "pkcs11" build tag to enable the production
// implementation. Without this tag, a stub implementation is used that
// returns ErrPKCS11Disabled for all operations.
//
// Build with PKCS#11 support:
//
//	go build -tags pkcs11 ./...
//
// # Usage
//
// Create a manager and register modules:
//
//	mgr := manager.New(manager.WithLogger(logger))
//	defer mgr.Close()
//
//	// Register a PKCS#11 module (e.g., SoftHSM2)
//	moduleID, err := mgr.RegisterModule("/usr/lib/softhsm/libsofthsm2.so", "SoftHSM")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// List available tokens
//	tokens, err := mgr.ListTokens()
//
//	// Connect to a token
//	backend, err := mgr.Connect(moduleID, 0, "userpin", "")
package manager
