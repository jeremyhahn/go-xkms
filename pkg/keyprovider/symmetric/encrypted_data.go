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

package symmetric

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// wireVersionExplicitNonce is every ciphertext this format produced before
// FIPS 140-only support: EncryptedData.GCMNonceMode is always the zero
// value (GCMNonceModeExplicit), so there is nothing to record and the wire
// bytes are unchanged from the original version-1 layout. This keeps every
// existing ciphertext, and every existing caller of Marshal, byte-for-byte
// compatible.
const wireVersionExplicitNonce byte = 0x01

// wireVersionWithNonceMode is written only when GCMNonceMode is not the
// zero value: one extra marker byte follows the version, naming which AEAD
// construction produced Nonce, so Unmarshal (and, in turn, Decrypt) can
// reconstruct the same construction regardless of the FIPS posture of the
// process that reads it back. See types.GCMNonceMode.
const wireVersionWithNonceMode byte = 0x02

const (
	nonceModeMarkerExplicit byte = 0x00
	nonceModeMarkerRandom   byte = 0x01
)

// gcmNonceModeMarker maps a types.GCMNonceMode onto its one-byte wire
// marker.
func gcmNonceModeMarker(mode types.GCMNonceMode) (byte, error) {
	switch mode {
	case types.GCMNonceModeExplicit:
		return nonceModeMarkerExplicit, nil
	case types.GCMNonceModeRandom:
		return nonceModeMarkerRandom, nil
	default:
		return 0, &errs.Message{Msg: fmt.Sprintf("unknown GCM nonce mode: %q", mode)}
	}
}

// gcmNonceModeFromMarker is the inverse of gcmNonceModeMarker.
func gcmNonceModeFromMarker(marker byte) (types.GCMNonceMode, error) {
	switch marker {
	case nonceModeMarkerExplicit:
		return types.GCMNonceModeExplicit, nil
	case nonceModeMarkerRandom:
		return types.GCMNonceModeRandom, nil
	default:
		return "", &errs.Message{Msg: fmt.Sprintf("unknown GCM nonce mode marker: 0x%02x", marker)}
	}
}

// Marshal serializes EncryptedData to bytes for storage/transmission.
// This implements a wire format that includes version, algorithm, nonce, tag, and ciphertext.
//
// Wire Format (version 1, ed.GCMNonceMode == types.GCMNonceModeExplicit):
//
//	┌────────────────────────────────────────────────────┐
//	│ Version: 1 byte (0x01)                             │
//	├────────────────────────────────────────────────────┤
//	│ Algorithm Length: 2 bytes (big-endian uint16)      │
//	│ Algorithm: variable bytes (UTF-8 string)           │
//	├────────────────────────────────────────────────────┤
//	│ Nonce Length: 2 bytes (big-endian uint16)          │
//	│ Nonce: variable bytes                              │
//	├────────────────────────────────────────────────────┤
//	│ Tag Length: 2 bytes (big-endian uint16)            │
//	│ Tag: variable bytes                                │
//	├────────────────────────────────────────────────────┤
//	│ Ciphertext Length: 4 bytes (big-endian uint32)     │
//	│ Ciphertext: variable bytes                         │
//	└────────────────────────────────────────────────────┘
//
// Wire Format (version 2, ed.GCMNonceMode != types.GCMNonceModeExplicit):
// identical to version 1, except one GCM nonce mode marker byte (0x00
// explicit, 0x01 random) is inserted immediately after the version byte, so
// Decrypt knows which AEAD construction to rebuild. Unmarshal accepts both
// versions; Marshal only ever emits version 2 when there is a non-explicit
// mode to record, so every ciphertext produced before this mode existed --
// and every ciphertext this format still produces for every non-GCM
// algorithm and every AES-GCM ciphertext outside FIPS 140-only -- keeps the
// version-1 wire bytes.
func Marshal(ed *types.EncryptedData) ([]byte, error) {
	if ed == nil {
		return nil, &errs.Message{Msg: "EncryptedData is nil"}
	}

	buf := new(bytes.Buffer)

	version := wireVersionExplicitNonce
	if ed.GCMNonceMode != types.GCMNonceModeExplicit {
		version = wireVersionWithNonceMode
	}

	// Version
	if err := buf.WriteByte(version); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to write version", Err: err}
	}

	// GCM nonce mode marker (version 2 only)
	if version == wireVersionWithNonceMode {
		marker, err := gcmNonceModeMarker(ed.GCMNonceMode)
		if err != nil {
			return nil, err
		}
		if err := buf.WriteByte(marker); err != nil {
			return nil, &errs.Wrapped{Msg: "failed to write GCM nonce mode marker", Err: err}
		}
	}

	// Algorithm
	algBytes := []byte(ed.Algorithm)
	if len(algBytes) > 65535 {
		return nil, &errs.Message{Msg: fmt.Sprintf("algorithm string too long: %d bytes", len(algBytes))}
	}
	// #nosec G115 - Length is validated to be <= 65535 before conversion
	if err := binary.Write(buf, binary.BigEndian, uint16(len(algBytes))); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to write algorithm length", Err: err}
	}
	if _, err := buf.Write(algBytes); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to write algorithm", Err: err}
	}

	// Nonce
	if len(ed.Nonce) > 65535 {
		return nil, &errs.Message{Msg: fmt.Sprintf("nonce too long: %d bytes", len(ed.Nonce))}
	}
	// #nosec G115 - Length is validated to be <= 65535 before conversion
	if err := binary.Write(buf, binary.BigEndian, uint16(len(ed.Nonce))); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to write nonce length", Err: err}
	}
	if _, err := buf.Write(ed.Nonce); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to write nonce", Err: err}
	}

	// Tag
	if len(ed.Tag) > 65535 {
		return nil, &errs.Message{Msg: fmt.Sprintf("tag too long: %d bytes", len(ed.Tag))}
	}
	// #nosec G115 - Length is validated to be <= 65535 before conversion
	if err := binary.Write(buf, binary.BigEndian, uint16(len(ed.Tag))); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to write tag length", Err: err}
	}
	if _, err := buf.Write(ed.Tag); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to write tag", Err: err}
	}

	// Ciphertext
	if uint64(len(ed.Ciphertext)) > 4294967295 {
		return nil, &errs.Message{Msg: fmt.Sprintf("ciphertext too long: %d bytes", len(ed.Ciphertext))}
	}
	// #nosec G115 - Length is validated to be <= 4294967295 before conversion
	if err := binary.Write(buf, binary.BigEndian, uint32(len(ed.Ciphertext))); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to write ciphertext length", Err: err}
	}
	if _, err := buf.Write(ed.Ciphertext); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to write ciphertext", Err: err}
	}

	return buf.Bytes(), nil
}

// Unmarshal deserializes EncryptedData from bytes.
// Returns an error if the data is malformed or uses an unsupported version.
func Unmarshal(data []byte) (*types.EncryptedData, error) {
	if len(data) < 1 {
		return nil, &errs.Message{Msg: "data too short: minimum 1 byte required"}
	}

	buf := bytes.NewReader(data)

	// Version
	version, err := buf.ReadByte()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read version", Err: err}
	}

	var nonceMode types.GCMNonceMode
	switch version {
	case wireVersionExplicitNonce:
		nonceMode = types.GCMNonceModeExplicit
	case wireVersionWithNonceMode:
		marker, err := buf.ReadByte()
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to read GCM nonce mode marker", Err: err}
		}
		nonceMode, err = gcmNonceModeFromMarker(marker)
		if err != nil {
			return nil, err
		}
	default:
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported version: 0x%02x", version)}
	}

	ed := &types.EncryptedData{GCMNonceMode: nonceMode}

	// Algorithm
	var algLen uint16
	if err := binary.Read(buf, binary.BigEndian, &algLen); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read algorithm length", Err: err}
	}
	algBytes := make([]byte, algLen)
	if _, err := io.ReadFull(buf, algBytes); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read algorithm", Err: err}
	}
	ed.Algorithm = string(algBytes)

	// Nonce
	var nonceLen uint16
	if err := binary.Read(buf, binary.BigEndian, &nonceLen); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read nonce length", Err: err}
	}
	ed.Nonce = make([]byte, nonceLen)
	if _, err := io.ReadFull(buf, ed.Nonce); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read nonce", Err: err}
	}

	// Tag
	var tagLen uint16
	if err := binary.Read(buf, binary.BigEndian, &tagLen); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read tag length", Err: err}
	}
	ed.Tag = make([]byte, tagLen)
	if _, err := io.ReadFull(buf, ed.Tag); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read tag", Err: err}
	}

	// Ciphertext
	var cipherLen uint32
	if err := binary.Read(buf, binary.BigEndian, &cipherLen); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read ciphertext length", Err: err}
	}
	ed.Ciphertext = make([]byte, cipherLen)
	if _, err := io.ReadFull(buf, ed.Ciphertext); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read ciphertext", Err: err}
	}

	return ed, nil
}

// Validate checks if the EncryptedData is valid for the specified algorithm.
func Validate(ed *types.EncryptedData) error {
	if ed == nil {
		return &errs.Message{Msg: "EncryptedData is nil"}
	}

	if ed.Algorithm == "" {
		return &errs.Message{Msg: "algorithm is required"}
	}

	if len(ed.Nonce) == 0 {
		return &errs.Message{Msg: "nonce is required"}
	}

	if len(ed.Tag) == 0 {
		return &errs.Message{Msg: "tag is required"}
	}

	if len(ed.Ciphertext) == 0 {
		return &errs.Message{Msg: "ciphertext is required"}
	}

	// Algorithm-specific validation
	switch ed.Algorithm {
	case string(types.SymmetricAES128GCM), string(types.SymmetricAES192GCM), string(types.SymmetricAES256GCM):
		// GCM standard nonce is 12 bytes
		if len(ed.Nonce) < 12 {
			return &errs.Message{Msg: fmt.Sprintf("GCM nonce must be at least 12 bytes, got %d", len(ed.Nonce))}
		}
		// GCM standard tag is 16 bytes
		if len(ed.Tag) != 16 {
			return &errs.Message{Msg: fmt.Sprintf("GCM tag must be 16 bytes, got %d", len(ed.Tag))}
		}
	case string(types.SymmetricChaCha20Poly1305):
		// ChaCha20-Poly1305 standard nonce is 12 bytes
		if len(ed.Nonce) != 12 {
			return &errs.Message{Msg: fmt.Sprintf("ChaCha20-Poly1305 nonce must be 12 bytes, got %d", len(ed.Nonce))}
		}
		// Poly1305 tag is 16 bytes
		if len(ed.Tag) != 16 {
			return &errs.Message{Msg: fmt.Sprintf("Poly1305 tag must be 16 bytes, got %d", len(ed.Tag))}
		}
	case string(types.SymmetricXChaCha20Poly1305):
		// XChaCha20-Poly1305 extended nonce is 24 bytes
		if len(ed.Nonce) != 24 {
			return &errs.Message{Msg: fmt.Sprintf("XChaCha20-Poly1305 nonce must be 24 bytes, got %d", len(ed.Nonce))}
		}
		// Poly1305 tag is 16 bytes
		if len(ed.Tag) != 16 {
			return &errs.Message{Msg: fmt.Sprintf("Poly1305 tag must be 16 bytes, got %d", len(ed.Tag))}
		}
	}

	return nil
}
