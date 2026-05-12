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

// Package ssh is the public SDK surface for SSH key, known-hosts,
// authorized-keys, and session management served by go-xkms.
//
// Four transports are planned:
//
//   - embedded (this phase): in-process; imports pkg/ssh/* directly.
//     Intended for xkey's standalone mode and for consumers that
//     embed xkms entirely.
//   - rest (Phase 1c): HTTP/JSON to xkmsd, with a custom passphrase
//     Unmarshaler that lands bytes in a secure.Buffer.
//   - grpc (stub): reserves the package name; implementation deferred.
//
// Every transport satisfies the Client interface. Callers should
// program against Client and let the embedded constructor pick the
// concrete implementation based on configuration.
//
// # Memory discipline
//
// DTOs defined here are safe to serialize: they carry no enclave
// handles and no plaintext private-key bytes. When callers need the
// enclaved private half (for Signer, Import, etc.) the SDK returns
// ssh.Signer values or *secure.Secret through side channels documented
// on each method.
package ssh
