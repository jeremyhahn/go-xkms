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

package pairing

import "encoding/binary"

// ShortAuthString derives a short, human-comparable code from session's
// attestation channel binding (#129's domain-separated SHA-256 of both
// sides' Noise static public keys and the identity-exchange prologue) for
// the operator to visually compare against the same value the phone
// displays during pairing (go-xkms#1306).
//
// It reuses AttestChannelBinding rather than deriving a second value: both
// answer the same question -- "do these two static keys belong to each
// other?" -- and the channel binding already commits to exactly that,
// symmetrically on both sides of the handshake (session.isInitiator flips
// which side is "initiator" in the hash, so both peers compute the same
// bytes). Binding to the identity static keys rather than the handshake's
// ephemeral contributions is deliberate, not a shortcut: an active MITM in
// the unauthenticated first-pairing XX handshake must present ITS OWN static
// key to each side (it does not hold either party's private key), so the
// two victims' independently computed codes would differ -- exactly the
// mismatch this code exists to make visible. It is available only after the
// handshake, for the same reason AttestChannelBinding is: there is no
// authenticated peer static key to bind to before it completes.
//
// The result is three four-digit groups, "####-####-####", each read from
// two bytes of the binding as a big-endian uint16 reduced mod 10000. This is
// not a substitute for the full 32-byte binding -- it is a human-checkable
// summary of it, the same role a Signal-style safety-number block plays.
func ShortAuthString(session *NoiseSession) (string, error) {
	binding, err := session.AttestChannelBinding()
	if err != nil {
		return "", err
	}
	return formatShortAuthString(binding), nil
}

// formatShortAuthString renders the first 6 bytes of binding as three
// four-digit decimal groups. Split out from ShortAuthString so the
// conformance vector test can pin the format against a fixed binding value
// without going through a live handshake.
func formatShortAuthString(binding []byte) string {
	group := func(b []byte) uint16 {
		return binary.BigEndian.Uint16(b) % 10000
	}
	return formatSASGroup(group(binding[0:2])) + "-" +
		formatSASGroup(group(binding[2:4])) + "-" +
		formatSASGroup(group(binding[4:6]))
}

// formatSASGroup zero-pads a group to exactly four digits.
func formatSASGroup(n uint16) string {
	digits := [4]byte{}
	for i := 3; i >= 0; i-- {
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[:])
}
