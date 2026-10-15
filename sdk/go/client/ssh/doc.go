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
// Six transports are implemented:
//
//   - embedded: in-process; imports pkg/ssh/* directly. Intended for
//     xkey's standalone mode and for consumers that embed xkms entirely.
//   - rest: HTTP/JSON to xkmsd, with a custom passphrase Unmarshaler
//     that lands bytes in a secure.Buffer.
//   - grpc: the xkmsd KeystoreService SSH RPCs.
//   - unix: gRPC over TLS on xkmsd's Unix domain socket.
//   - quic: HTTP/3 with the same JSON wire format as rest.
//   - mcp: JSON-RPC 2.0 over TCP, the same wire format as
//     pkg/api/transport/mcp.
//
// Every transport satisfies the Client interface. Callers should
// program against Client and let NewClientForServer pick the concrete
// implementation based on configuration.
//
// # Session.Dial across transports
//
// SessionClient.Dial establishes an outbound SSH connection to a target
// host chosen by the caller — not to xkmsd itself. Every transport
// supports it: the SSH connection is always dialed directly from the
// caller's own process using golang.org/x/crypto/ssh, so it needs no
// byte-stream support from the transport. The transport is used only for
// two RPCs: KeysClient.Signer, which returns a forward-signing proxy so
// the authentication private key never leaves xkmsd, and
// KnownHostsClient.Callback, which verifies each inbound host key against
// the server's pins before the handshake completes. Host-key verification
// fails closed — an unrecognized or mismatched host key is a typed error
// (*NotFoundError, *MismatchError); there is no trust-on-first-use path.
//
// Client.Console is different: it needs a persistent, interactive byte
// stream, which only the embedded transport (the PTY runs in the caller's
// own process) and the REST/QUIC WebSocket bridge support. gRPC/unix and
// MCP return *ConsoleUnsupportedError for Console — never for Session.Dial.
//
// # Memory discipline
//
// DTOs defined here are safe to serialize: they carry no enclave
// handles and no plaintext private-key bytes. When callers need the
// enclaved private half (for Signer, Import, etc.) the SDK returns
// ssh.Signer values or *secure.Secret through side channels documented
// on each method.
package ssh
