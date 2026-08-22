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

package phone

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// DeviceFingerprintSize is the length in bytes of a device fingerprint, fixed
// by the wire contract: the identity ack for a known device is one status byte
// followed by the fingerprint (pairing.IdentityAckKnownSize), and both
// producers hash with SHA-256. Deriving it from the wire constant rather than
// restating 32 keeps the two from drifting apart.
const DeviceFingerprintSize = pairing.IdentityAckKnownSize - 1

// Compile-time check that the wire contract and SHA-256 still agree. If the
// identity ack ever carries a different digest, this is where it is noticed.
var _ [DeviceFingerprintSize]byte = [sha256.Size]byte{}

// ErrInvalidDeviceFingerprint reports that a stored device fingerprint is
// present but is not a usable fingerprint -- it does not decode as hex, or it
// decodes to the wrong number of bytes. It is deliberately distinct from "no
// fingerprint configured": the two states carry opposite authorization
// meanings and callers must be able to tell them apart.
var ErrInvalidDeviceFingerprint = errors.New("phone: stored device fingerprint is not valid hex")

// InvalidDeviceFingerprintError carries the undecodable fingerprint alongside
// the decoding cause so an operator can see which stored value is at fault.
// The value is device-identifying material, not a secret — it is the hash the
// device presents on the wire during the handshake.
type InvalidDeviceFingerprintError struct {
	// Value is a BOUNDED PREFIX of the offending fingerprint — at most
	// maxReportedFingerprint characters — not the whole of it. Truncating at
	// construction rather than at formatting is what actually bounds the
	// retention: an error that formats to something short while holding a
	// megabyte of corrupted config keeps that megabyte alive for as long as
	// anything holds the error.
	Value string

	// ValueLen is the length of the ORIGINAL value in characters, which Value
	// no longer tells you once it has been truncated. Zero means unset.
	ValueLen int

	// Err is the decoding cause. It may be nil in a value constructed by hand;
	// Error and Unwrap both tolerate that.
	Err error
}

// maxReportedFingerprint bounds how much of an offending value reaches an
// error string and, through it, the log. The value is device-identifying
// material rather than a secret, but a corrupted config can carry an
// arbitrarily long one, and neither an error nor a log line is a good place
// to put it in full.
const maxReportedFingerprint = 32

// newInvalidDeviceFingerprintError builds the error with the value already
// truncated, so no caller can create one that retains an unbounded string.
func newInvalidDeviceFingerprintError(value string, err error) *InvalidDeviceFingerprintError {
	shown := value
	if len(shown) > maxReportedFingerprint {
		shown = shown[:maxReportedFingerprint]
	}
	return &InvalidDeviceFingerprintError{Value: shown, ValueLen: len(value), Err: err}
}

// Error implements the error interface.
//
// Nil-safe in every part, because the type and its fields are EXPORTED: any
// downstream package can legitimately construct a zero value or set Value
// without Err, and formatting or logging one must not take the process down.
// An error type that panics while being reported turns a handled failure into
// an outage, which is a strictly worse outcome than the one it describes.
func (e *InvalidDeviceFingerprintError) Error() string {
	if e == nil {
		return ErrInvalidDeviceFingerprint.Error() + ": <nil>"
	}

	// Reported length prefers ValueLen, which survives truncation, and falls
	// back to the retained prefix for a hand-built value that never set it.
	length := e.ValueLen
	if length < len(e.Value) {
		length = len(e.Value)
	}

	shown := e.Value
	if len(shown) > maxReportedFingerprint {
		shown = shown[:maxReportedFingerprint]
	}
	if length > len(shown) {
		shown += "... (" + strconv.Itoa(length) + " chars)"
	}

	msg := ErrInvalidDeviceFingerprint.Error() + ": " + shown
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the sentinel and the decoding cause so errors.Is matches
// both ErrInvalidDeviceFingerprint and the underlying hex error.
//
// The cause is omitted when nil rather than returned as a nil element: a nil
// in the slice is a trap for anything walking the tree by hand, and it says
// "there is a cause" when there is not.
func (e *InvalidDeviceFingerprintError) Unwrap() []error {
	if e == nil || e.Err == nil {
		return []error{ErrInvalidDeviceFingerprint}
	}
	return []error{ErrInvalidDeviceFingerprint, e.Err}
}

// DecodeDeviceFingerprint decodes a stored device fingerprint into the byte
// form PerformHandshake compares against the value the device presents.
//
// The fingerprint binds a pairing record to the physical device it authorizes,
// so decoding it FAILS CLOSED. An empty string is the legitimate "no
// fingerprint policy configured" state and yields (nil, nil). A non-empty
// string that does not decode yields an *InvalidDeviceFingerprintError and no
// bytes — never (nil, nil).
//
// That distinction is the whole point of this function. Returning nil for a
// malformed value would hand the handshake the same "no expected fingerprint"
// signal an unconfigured device gives it, which silently downgrades an
// identity-bound handshake into an unbound one. Corrupted authorization
// material must never be less restrictive than the policy it corrupts: an
// attacker able to write the config file could otherwise flip one character to
// turn "only this device" into "any device that completes the handshake".
func DecodeDeviceFingerprint(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}

	// LENGTH FIRST, before decoding. A fingerprint of the wrong length is
	// stored authorization data that can never match -- the device always
	// presents exactly DeviceFingerprintSize bytes -- so checking it here
	// costs nothing and refuses the value where it is, rather than letting the
	// handshake report "device fingerprint mismatch" and accuse the device of
	// being the wrong one when the stored record is simply unusable.
	//
	// Checking BEFORE hex.DecodeString also bounds the work and the exposure:
	// a corrupted or synchronised config carrying a megabyte of valid hex
	// would otherwise allocate half its size, be retained in the error, and be
	// logged verbatim by every caller. Nothing here needs to decode a value
	// already known to be the wrong size.
	if len(encoded) != hex.EncodedLen(DeviceFingerprintSize) {
		return nil, newInvalidDeviceFingerprintError(encoded,
			errors.New("is "+strconv.Itoa(len(encoded))+" characters, want "+
				strconv.Itoa(hex.EncodedLen(DeviceFingerprintSize))))
	}

	fingerprint, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, newInvalidDeviceFingerprintError(encoded, err)
	}
	return fingerprint, nil
}
