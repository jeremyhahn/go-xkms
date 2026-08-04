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

// Marshal serializes EncryptedData to bytes for storage/transmission.
// This implements a wire format that includes version, algorithm, nonce, tag, and ciphertext.
//
// Wire Format (version 1):
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
func Marshal(ed *types.EncryptedData) ([]byte, error) {
	if ed == nil {
		return nil, &errs.Message{Msg: "EncryptedData is nil"}
	}

	buf := new(bytes.Buffer)

	// Version
	if err := buf.WriteByte(0x01); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to write version", Err: err}
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
	if version != 0x01 {
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported version: 0x%02x", version)}
	}

	ed := &types.EncryptedData{}

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
