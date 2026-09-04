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

package pivcert

// Construction of PIV attestation extensions.
//
// This exists so a caller — a test, an emulated authenticator, a fixture
// generator — can build a certificate carrying the extensions ParseAttestation
// reads. It is the encoder counterpart of the parser and it deliberately does
// NOT define the format: both sides implement the same documented layout, so
// agreeing with each other proves only that they are consistent, never that
// either matches a physical device.
//
// That is why the parser is strict and why this package's tests include a
// certificate whose framing differs from this encoder's. Reading this file as
// evidence that the wire format is correct would be reading a mirror.

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// BuildAttestationExtensions returns the pkix extensions describing att.
//
// Only the fields that are set are emitted; a nil field produces no extension,
// which is how an absent extension is represented on a real device. Entries in
// att.Unparseable are ignored — this builder emits well-formed values, and a
// test wanting a malformed one should construct that extension directly.
func BuildAttestationExtensions(att *Attestation) ([]pkix.Extension, error) {
	if att == nil {
		return nil, &VerifyError{Reason: "attestation is nil"}
	}

	var exts []pkix.Extension

	if v := att.FirmwareVersion; v != nil {
		exts = append(exts, pkix.Extension{
			Id:    OIDFirmwareVersion,
			Value: []byte{v.Major, v.Minor, v.Patch},
		})
	}

	if n := att.SerialNumber; n != nil {
		encoded, err := asn1.Marshal(new(big.Int).SetUint64(*n))
		if err != nil {
			return nil, &VerifyError{Reason: "encoding serial number: " + err.Error()}
		}
		exts = append(exts, pkix.Extension{Id: OIDSerialNumber, Value: encoded})
	}

	// The PIN and touch policies share one two-byte extension, so both must be
	// present to emit it. A device reports them together or not at all.
	if att.PINPolicy != nil && att.TouchPolicy != nil {
		exts = append(exts, pkix.Extension{
			Id:    OIDPINTouchPolicy,
			Value: []byte{byte(*att.PINPolicy), byte(*att.TouchPolicy)},
		})
	}

	if f := att.FormFactor; f != nil {
		exts = append(exts, pkix.Extension{
			Id:    OIDFormFactor,
			Value: []byte{byte(*f)},
		})
	}

	return exts, nil
}
