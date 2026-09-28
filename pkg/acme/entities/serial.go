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

package entities

import (
	"math/big"
	"strings"
)

// InvalidSerialError indicates that a certificate serial number string could
// not be parsed as a positive hexadecimal integer.
type InvalidSerialError struct {
	// Serial is the offending input, as received.
	Serial string
}

// Error implements the error interface.
func (e *InvalidSerialError) Error() string {
	return "acme: invalid certificate serial \"" + e.Serial + "\""
}

// NormalizeSerial validates a certificate serial number supplied as a
// hexadecimal string - as carried in ACME certificate URLs and stored in
// ACMECertificate.Serial - and returns its canonical form: lowercase,
// unpadded hexadecimal, with no "0x"/"0X" prefix.
//
// Canonicalizing means different textual encodings of the same serial
// (leading zeros, uppercase hex digits, an optional "0x" prefix) normalize
// to the same Serial value and therefore the same DAO lookup key.
//
// Returns *InvalidSerialError if s is empty, is not valid hexadecimal, or
// decodes to a non-positive integer (RFC 5280 Section 4.1.2.2 requires
// certificate serial numbers to be positive).
func NormalizeSerial(s string) (string, error) {
	trimmed := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if trimmed == "" {
		return "", &InvalidSerialError{Serial: s}
	}

	serial, ok := new(big.Int).SetString(trimmed, 16)
	if !ok || serial.Sign() <= 0 {
		return "", &InvalidSerialError{Serial: s}
	}

	return serial.Text(16), nil
}
