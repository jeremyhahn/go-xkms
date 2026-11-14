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

// Package securityevent is the format of an HSM device's tamper-response
// record (SPEC row device-security-event-evidence, #1765): RFC 9334
// Evidence about the device's Attesting Environment, carried as one CBOR
// Claims-Set (docs/attestation-evidence/architecture.md, "Device
// security-event record").
//
// The Claims-Set is {ClaimKey: record} in RFC 8949 §4.2.1 core
// deterministic encoding, with integer keys only:
//
//	record = {1: count, 2: dropped, 3: [entry, ...]}
//	entry  = {1: at, 2: kind, 3: what, 4: result}
//
// Each value is an unsigned integer as wide as the device's reply field:
// count u8, dropped u16 (saturating), at u32, kind, what and result u8.
//
// Encode writes a Record and Decode reads one back. Decode accepts only
// the deterministic encoding of a well-formed record and names the first
// rule the input breaks with one of the errors in errors.go.
//
// The package does not decide how the record is bound to the device (the
// binding question in the architecture document): it neither signs nor
// verifies, and does not check a nonce. A backend hands the encoded
// Claims-Set over through types.SecurityEventProvider.
package securityevent
