// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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

	"github.com/jeremyhahn/go-keychain/pkg/types"
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
		return nil, fmt.Errorf("EncryptedData is nil")
	}

	buf := new(bytes.Buffer)

	// Version
	if err := buf.WriteByte(0x01); err != nil {
		return nil, fmt.Errorf("failed to write version: %w", err)
	}

	// Algorithm
	algBytes := []byte(ed.Algorithm)
	if len(algBytes) > 65535 {
		return nil, fmt.Errorf("algorithm string too long: %d bytes", len(algBytes))
	}
	// #nosec G115 - Length is validated to be <= 65535 before conversion
	if err := binary.Write(buf, binary.BigEndian, uint16(len(algBytes))); err != nil {
		return nil, fmt.Errorf("failed to write algorithm length: %w", err)
	}
	if _, err := buf.Write(algBytes); err != nil {
		return nil, fmt.Errorf("failed to write algorithm: %w", err)
	}

	// Nonce
	if len(ed.Nonce) > 65535 {
		return nil, fmt.Errorf("nonce too long: %d bytes", len(ed.Nonce))
	}
	// #nosec G115 - Length is validated to be <= 65535 before conversion
	if err := binary.Write(buf, binary.BigEndian, uint16(len(ed.Nonce))); err != nil {
		return nil, fmt.Errorf("failed to write nonce length: %w", err)
	}
	if _, err := buf.Write(ed.Nonce); err != nil {
		return nil, fmt.Errorf("failed to write nonce: %w", err)
	}

	// Tag
	if len(ed.Tag) > 65535 {
		return nil, fmt.Errorf("tag too long: %d bytes", len(ed.Tag))
	}
	// #nosec G115 - Length is validated to be <= 65535 before conversion
	if err := binary.Write(buf, binary.BigEndian, uint16(len(ed.Tag))); err != nil {
		return nil, fmt.Errorf("failed to write tag length: %w", err)
	}
	if _, err := buf.Write(ed.Tag); err != nil {
		return nil, fmt.Errorf("failed to write tag: %w", err)
	}

	// Ciphertext
	if uint64(len(ed.Ciphertext)) > 4294967295 {
		return nil, fmt.Errorf("ciphertext too long: %d bytes", len(ed.Ciphertext))
	}
	// #nosec G115 - Length is validated to be <= 4294967295 before conversion
	if err := binary.Write(buf, binary.BigEndian, uint32(len(ed.Ciphertext))); err != nil {
		return nil, fmt.Errorf("failed to write ciphertext length: %w", err)
	}
	if _, err := buf.Write(ed.Ciphertext); err != nil {
		return nil, fmt.Errorf("failed to write ciphertext: %w", err)
	}

	return buf.Bytes(), nil
}

// Unmarshal deserializes EncryptedData from bytes.
// Returns an error if the data is malformed or uses an unsupported version.
func Unmarshal(data []byte) (*types.EncryptedData, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short: minimum 1 byte required")
	}

	buf := bytes.NewReader(data)

	// Version
	version, err := buf.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	if version != 0x01 {
		return nil, fmt.Errorf("unsupported version: 0x%02x", version)
	}

	ed := &types.EncryptedData{}

	// Algorithm
	var algLen uint16
	if err := binary.Read(buf, binary.BigEndian, &algLen); err != nil {
		return nil, fmt.Errorf("failed to read algorithm length: %w", err)
	}
	algBytes := make([]byte, algLen)
	if _, err := buf.Read(algBytes); err != nil {
		return nil, fmt.Errorf("failed to read algorithm: %w", err)
	}
	ed.Algorithm = string(algBytes)

	// Nonce
	var nonceLen uint16
	if err := binary.Read(buf, binary.BigEndian, &nonceLen); err != nil {
		return nil, fmt.Errorf("failed to read nonce length: %w", err)
	}
	ed.Nonce = make([]byte, nonceLen)
	if _, err := buf.Read(ed.Nonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	// Tag
	var tagLen uint16
	if err := binary.Read(buf, binary.BigEndian, &tagLen); err != nil {
		return nil, fmt.Errorf("failed to read tag length: %w", err)
	}
	ed.Tag = make([]byte, tagLen)
	if _, err := buf.Read(ed.Tag); err != nil {
		return nil, fmt.Errorf("failed to read tag: %w", err)
	}

	// Ciphertext
	var cipherLen uint32
	if err := binary.Read(buf, binary.BigEndian, &cipherLen); err != nil {
		return nil, fmt.Errorf("failed to read ciphertext length: %w", err)
	}
	ed.Ciphertext = make([]byte, cipherLen)
	if _, err := buf.Read(ed.Ciphertext); err != nil {
		return nil, fmt.Errorf("failed to read ciphertext: %w", err)
	}

	return ed, nil
}

// Validate checks if the EncryptedData is valid for the specified algorithm.
func Validate(ed *types.EncryptedData) error {
	if ed == nil {
		return fmt.Errorf("EncryptedData is nil")
	}

	if ed.Algorithm == "" {
		return fmt.Errorf("algorithm is required")
	}

	if len(ed.Nonce) == 0 {
		return fmt.Errorf("nonce is required")
	}

	if len(ed.Tag) == 0 {
		return fmt.Errorf("tag is required")
	}

	if len(ed.Ciphertext) == 0 {
		return fmt.Errorf("ciphertext is required")
	}

	// Algorithm-specific validation
	switch ed.Algorithm {
	case string(types.SymmetricAES128GCM), string(types.SymmetricAES192GCM), string(types.SymmetricAES256GCM):
		// GCM standard nonce is 12 bytes
		if len(ed.Nonce) < 12 {
			return fmt.Errorf("GCM nonce must be at least 12 bytes, got %d", len(ed.Nonce))
		}
		// GCM standard tag is 16 bytes
		if len(ed.Tag) != 16 {
			return fmt.Errorf("GCM tag must be 16 bytes, got %d", len(ed.Tag))
		}
	case string(types.SymmetricChaCha20Poly1305):
		// ChaCha20-Poly1305 standard nonce is 12 bytes
		if len(ed.Nonce) != 12 {
			return fmt.Errorf("ChaCha20-Poly1305 nonce must be 12 bytes, got %d", len(ed.Nonce))
		}
		// Poly1305 tag is 16 bytes
		if len(ed.Tag) != 16 {
			return fmt.Errorf("Poly1305 tag must be 16 bytes, got %d", len(ed.Tag))
		}
	case string(types.SymmetricXChaCha20Poly1305):
		// XChaCha20-Poly1305 extended nonce is 24 bytes
		if len(ed.Nonce) != 24 {
			return fmt.Errorf("XChaCha20-Poly1305 nonce must be 24 bytes, got %d", len(ed.Nonce))
		}
		// Poly1305 tag is 16 bytes
		if len(ed.Tag) != 16 {
			return fmt.Errorf("Poly1305 tag must be 16 bytes, got %d", len(ed.Tag))
		}
	}

	return nil
}
