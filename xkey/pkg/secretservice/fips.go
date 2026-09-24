// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package secretservice

import "crypto/fips140"

// fipsMode reports whether this process is under FIPS 140 rules, by asking
// the Go standard library directly (go-xkms #21): GODEBUG=fips140=on|only at
// runtime, or a GOFIPS140 build, both surface through crypto/fips140.Enabled.
// go-xkms never keeps its own approved-algorithm allowlist; FIPS enforcement
// is entirely the stdlib's job (see fips-stdlib-only in the project memory).
//
// dh-ietf1024-sha256-aes128-cbc-pkcs7 (RFC 2409 Group 14 Diffie-Hellman with
// a raw SHA-256 key derivation and AES-128-CBC) is refused under FIPS
// enforcement: the ad hoc SHA-256-truncation KDF in crypto.go is not an
// approved key-derivation construction (SP 800-56A/SP 800-135), even though
// the underlying AES-CBC and SHA-256 primitives are themselves approved.
// OpenSession offers only the plain algorithm in that mode, which is safe
// here because org.freedesktop.secrets is reachable only over the local,
// kernel-mediated D-Bus session bus, not a network channel.
//
// It is a variable rather than a direct call so a test can drive both sides
// of the gate without running the suite twice under different environments.
var fipsMode = fips140.Enabled
