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

package fido2

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Authenticator data flag bits, as defined by WebAuthn Level 3 6.1.
const (
	// FlagUserPresent (UP) reports that the user was present.
	FlagUserPresent byte = 1 << 0

	// FlagUserVerified (UV) reports that the user was verified.
	FlagUserVerified byte = 1 << 2

	// FlagBackupEligible (BE) reports that the credential may be backed up.
	FlagBackupEligible byte = 1 << 3

	// FlagBackupState (BS) reports that the credential is backed up.
	FlagBackupState byte = 1 << 4

	// FlagAttestedCredentialData (AT) reports that attested credential
	// data follows the fixed header.
	FlagAttestedCredentialData byte = 1 << 6

	// FlagExtensionData (ED) reports that a CBOR extension-output map
	// terminates the authenticator data.
	FlagExtensionData byte = 1 << 7
)

// Authenticator data field sizes, as defined by WebAuthn Level 3 6.1 and
// 6.5.2.
const (
	// authDataRPIDHashLen is the size of the leading SHA-256 RP ID hash.
	authDataRPIDHashLen = 32

	// authDataHeaderLen is the size of the fixed header:
	// rpIdHash(32) + flags(1) + signCount(4).
	authDataHeaderLen = authDataRPIDHashLen + 1 + 4

	// aaguidLen is the size of the authenticator AAGUID.
	aaguidLen = 16

	// credentialIDLenFieldLen is the size of the big-endian credential ID
	// length field.
	credentialIDLenFieldLen = 2

	// maxCredentialIDLen is the largest credential ID a conforming
	// authenticator may report (WebAuthn Level 3 6.5.2).
	maxCredentialIDLen = 1023

	// cborMajorTypeMap is the CBOR major type of a map (RFC 8949 3.1).
	cborMajorTypeMap = 5
)

// authDataDecMode decodes the CBOR items embedded in authenticator data
// under the CTAP2 canonical CBOR profile (CTAP 2.1 6). Authenticator data
// is attacker-reachable, so the decoder rejects encodings a conforming
// authenticator never emits: indefinite-length items and excessive nesting
// are rejected by the well-formedness pass applied to every item, and
// duplicate map keys and invalid UTF-8 text are rejected when the
// extension map is materialized.
var authDataDecMode = mustDecMode(cbor.DecOptions{
	DupMapKey:       cbor.DupMapKeyEnforcedAPF,
	IndefLength:     cbor.IndefLengthForbidden,
	UTF8:            cbor.UTF8RejectInvalid,
	MaxNestedLevels: 16,
})

// mustDecMode builds a CBOR decode mode, panicking if the options are
// invalid. The options are compile-time constants, so a failure here is a
// programming error rather than a runtime condition.
func mustDecMode(opts cbor.DecOptions) cbor.DecMode {
	mode, err := opts.DecMode()
	if err != nil {
		panic("fido2: invalid CBOR decode options: " + err.Error())
	}
	return mode
}

// ParseAuthDataExtensions parses the CBOR extension-output map from
// authenticator data. It is the helper used to extract extension outputs
// such as hmac-secret from a MakeCredential or GetAssertion response.
//
// Authenticator data is laid out as (WebAuthn Level 3 6.1):
//
//	rpIdHash(32) || flags(1) || signCount(4)
//	  || attestedCredentialData   (only when the AT flag is set)
//	  || extensions               (only when the ED flag is set)
//
// and attested credential data as (WebAuthn Level 3 6.5.2):
//
//	aaguid(16) || credentialIdLength(2, big-endian)
//	  || credentialId(credentialIdLength)
//	  || credentialPublicKey(COSE_Key, CBOR)
//
// Because the COSE public key is variable-length CBOR, the extension map
// can only be located by decoding that key and measuring how many bytes it
// occupies; ParseAuthDataExtensions does exactly that.
//
// It returns (nil, nil) when the ED flag is clear, which is the sole case
// meaning "this authenticator data carries no extensions". Every malformed
// or truncated input yields a non-nil error wrapping one of
// ErrAuthDataTooShort, ErrInvalidAttestedCredentialData, ErrInvalidCOSEKey,
// ErrInvalidExtensions, or ErrAuthDataTrailingBytes.
func ParseAuthDataExtensions(authData []byte) (map[string]interface{}, error) {
	if len(authData) < authDataHeaderLen {
		return nil, &errs.Detail{
			Err:    ErrAuthDataTooShort,
			Detail: fmt.Sprintf("got %d bytes", len(authData)),
		}
	}

	flags := authData[authDataRPIDHashLen]
	if flags&FlagExtensionData == 0 {
		return nil, nil
	}

	offset := authDataHeaderLen
	if flags&FlagAttestedCredentialData != 0 {
		consumed, err := attestedCredentialDataLen(authData[offset:])
		if err != nil {
			return nil, err
		}
		offset += consumed
	}

	return decodeExtensions(authData[offset:])
}

// attestedCredentialDataLen returns the number of bytes the attested
// credential data at the front of b occupies.
func attestedCredentialDataLen(b []byte) (int, error) {
	header := aaguidLen + credentialIDLenFieldLen
	if len(b) < header {
		return 0, &errs.Detail{
			Err:    ErrInvalidAttestedCredentialData,
			Detail: fmt.Sprintf("need %d bytes for aaguid and credential ID length, got %d", header, len(b)),
		}
	}

	credIDLen := int(binary.BigEndian.Uint16(b[aaguidLen:header]))
	if credIDLen > maxCredentialIDLen {
		return 0, &errs.Detail{
			Err:    ErrInvalidAttestedCredentialData,
			Detail: fmt.Sprintf("credential ID length %d exceeds the %d-byte maximum", credIDLen, maxCredentialIDLen),
		}
	}

	offset := header + credIDLen
	if len(b) < offset {
		return 0, &errs.Detail{
			Err:    ErrInvalidAttestedCredentialData,
			Detail: fmt.Sprintf("credential ID length %d exceeds the %d remaining bytes", credIDLen, len(b)-header),
		}
	}

	keyLen, err := coseKeyLen(b[offset:])
	if err != nil {
		return 0, err
	}

	return offset + keyLen, nil
}

// coseKeyLen returns the number of bytes the COSE_Key at the front of b
// occupies. The key is decoded rather than interpreted: a COSE_Key is a
// CBOR map (RFC 9052 7), so decoding one item both validates the encoding
// and reveals where the extension map begins.
func coseKeyLen(b []byte) (int, error) {
	raw, consumed, err := decodeItem(b)
	if err != nil {
		return 0, &errs.Joined{Lead: ErrInvalidCOSEKey, Cause: err}
	}
	if !isCBORMap(raw) {
		return 0, &errs.Detail{
			Err:    ErrInvalidCOSEKey,
			Detail: fmt.Sprintf("expected a CBOR map, got major type %d", raw[0]>>5),
		}
	}
	return consumed, nil
}

// decodeExtensions decodes the extension-output map that terminates
// authenticator data. Trailing bytes are rejected: authenticator data ends
// with the extension map, so anything after it indicates a corrupted or
// tampered structure.
func decodeExtensions(b []byte) (map[string]interface{}, error) {
	raw, consumed, err := decodeItem(b)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidExtensions, Cause: err}
	}
	if !isCBORMap(raw) {
		return nil, &errs.Detail{
			Err:    ErrInvalidExtensions,
			Detail: fmt.Sprintf("expected a CBOR map, got major type %d", raw[0]>>5),
		}
	}
	if consumed != len(b) {
		return nil, &errs.Detail{
			Err:    ErrAuthDataTrailingBytes,
			Detail: fmt.Sprintf("%d bytes remain after the extension map", len(b)-consumed),
		}
	}

	extensions := make(map[string]interface{})
	if err := authDataDecMode.Unmarshal(raw, &extensions); err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidExtensions, Cause: err}
	}
	return extensions, nil
}

// decodeItem decodes the single CBOR item at the front of b, returning its
// raw encoding and the number of bytes it consumed. Trailing data after
// the item is left for the caller to handle.
func decodeItem(b []byte) (cbor.RawMessage, int, error) {
	if len(b) == 0 {
		return nil, 0, ErrCBORTruncated
	}

	dec := authDataDecMode.NewDecoder(bytes.NewReader(b))
	var raw cbor.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, 0, err
	}
	return raw, dec.NumBytesRead(), nil
}

// isCBORMap reports whether the raw CBOR item is a map.
func isCBORMap(raw cbor.RawMessage) bool {
	return len(raw) > 0 && raw[0]>>5 == cborMajorTypeMap
}
