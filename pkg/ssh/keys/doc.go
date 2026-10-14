// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

// Package keys owns SSH key material management for go-xkms: in-memory
// representation, PEM parsing (with and without passphrases), random
// generation, stable OpenSSH-format fingerprints, secure-memory-backed
// signers, and pluggable persistence against storage.Backend.
//
// The package is the only place in the repository that may call
// golang.org/x/crypto/ssh.ParsePrivateKey or
// ParsePrivateKeyWithPassphrase — every other caller MUST go through
// ParsePEM. A custom go vet analyzer enforces that invariant.
//
// # Memory discipline
//
// Long-lived key material lives in *secure.Secret, encrypted inside a
// go-enclave sealed enclave. Short-lived PEM plaintext used during parsing and
// signing flows through *secure.Buffer with immediate Destroy() on
// every return path. No caller ever holds plaintext key bytes in an
// unprotected []byte beyond a single stack frame.
//
// # Layering
//
// keys depends on pkg/ssh/scope for key identifiers and pkg/storage for
// persistence; it does NOT depend on any legacy xkey agent
// package. Phase 1c completed the xkey SDK rewrite and removed the legacy
// agent package; only the SDK-facing surface remains.
package keys
