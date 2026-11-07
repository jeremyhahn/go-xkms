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

package avr

// The alias certificate a real device emits, frozen.
//
// Mirrored from trusted-firmware's testdata/uccs_vectors.h, where it is a
// LITERAL and not a value computed from the firmware that produces it. It was
// made once by an independent encoder, checked against OpenSSL and Python
// `cryptography`, and pinned: the signature is a real ECDSA signature that
// verifies over the parser's own TBS bytes, and the subject key is a real point
// on P-256.
//
// A FAILURE HERE IS A WIRE BREAK, NOT A TEST TO UPDATE. These are the bytes
// every already-provisioned device puts on the wire, and this package is a
// verifier of them. If this stops parsing, either the profile changed under a
// fleet that cannot be recalled, or this package broke -- and both are worth
// stopping for.
//
// It is mirrored rather than imported because the SDK does not export it: the
// vector lives beside the firmware's own contract file, not in the Go module.
// That makes this a second copy, which is a cost accepted deliberately, and the
// reason it is acceptable is that neither copy is generated -- both are frozen
// literals of the same fact, so a drift is a test failure rather than two
// implementations agreeing with each other about something wrong.
const (
	// vecAliasCertNonceHex is the enrolment challenge inside the vector: 00..1F,
	// THIRTY-TWO bytes. Not the evidence frame's sixteen; the two widths are
	// different on purpose and must not be merged.
	vecAliasCertNonceHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	// vecAliasCertUeidHex is the ueid the claims set carries at CWT key 256,
	// with its leading 0x01 RAND type byte.
	vecAliasCertUeidHex = "01a1b2c3d4e5f60718293a4b5c6d7e8f90"

	// vecAliasCertHex is the whole certificate, 471 bytes of DER.
	vecAliasCertHex = "" +
		"308201d33082017aa00302010202084001020304050607300a06082a8648ce3d" +
		"0403023016311430120603550403130b61672044657669636549443020170d32" +
		"30303130313030303030305a180f39393939313233313233353935395a301331" +
		"11300f06035504031308616720416c6961733059301306072a8648ce3d020106" +
		"082a8648ce3d03010703420004798953e7e8134fdf3c139f63d3fbccc252a28b" +
		"6ca5059e618374a81231240f3fc83267aec725e18b66176c3685d1257201a670" +
		"33819585a22a296350159ae70ba381b23081af3081ac06066781050504060101" +
		"ff04819e30819b048198a30a5820000102030405060708090a0b0c0d0e0f1011" +
		"12131415161718191a1b1c1d1e1f1901005101a1b2c3d4e5f60718293a4b5c6d" +
		"7e8f9019011181821901025855a500505eec7874aaa557fdaaaef3f9fe0ccfb4" +
		"016561672d667702a2181f62616718210103a111a20782015820ba7816bf8f01" +
		"cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad181863617070" +
		"0c00300a06082a8648ce3d040302034700304402202f79b26e954e1e7523e979" +
		"dff8630a55271b0635dec8e88feaa4f72c54aaeeff02207778dba4b957648559" +
		"9fa7b12997a9395458151c7366e50762d6d36233f5eabb"
)
