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

// Package known_hosts manages pinned SSH host fingerprints for MITM-safe
// session establishment.
//
// Fingerprints are public material (OpenSSH "SHA256:..." form) and are
// persisted via the same storage.Backend used by pkg/ssh/keys. Because
// pins carry no secret material, they are not wrapped in memguard
// enclaves; storage-layer integrity (HMAC tag on QRDB's sealed backend,
// or file permissions for the local file backend) is sufficient.
//
// # Layering
//
// known_hosts depends on pkg/ssh/scope for identifier construction and
// on pkg/storage for persistence. It knows nothing about pkg/ssh/keys or
// pkg/ssh/session — the session package composes known_hosts+keys.
//
// # Typical call graph
//
// A consumer calls Callback(ctx, store, scope, owner) to obtain an
// ssh.HostKeyCallback, installs it on an ssh.ClientConfig, and dials.
// On first contact with an unpinned host the callback returns a typed
// error — pinning is an explicit operator action via Store.Add.
//
// Callers that want trust-on-first-use instead use
// CallbackWithConfirm(ctx, store, scope, owner, confirm): it behaves
// exactly like Callback, except an unpinned host is offered to a
// Confirmer (an operator prompt or an automated accept-new policy)
// instead of being rejected outright. A conflicting pin still hard-fails
// without ever reaching the Confirmer — TOFU covers absence, never a
// mismatch.
package known_hosts
