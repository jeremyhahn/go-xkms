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
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// chacha20Key implements types.SymmetricKey for ChaCha20-Poly1305 keys.
type chacha20Key struct {
	algorithm string
	keySize   int
	keyData   []byte
}

// Algorithm returns the symmetric algorithm identifier.
func (k *chacha20Key) Algorithm() string {
	return k.algorithm
}

// KeySize returns the key size in bits.
func (k *chacha20Key) KeySize() int {
	return k.keySize
}

// Raw returns a copy of the raw key bytes to prevent external modification.
func (k *chacha20Key) Raw() ([]byte, error) {
	// Return a copy to prevent modification
	raw := make([]byte, len(k.keyData))
	copy(raw, k.keyData)
	return raw, nil
}

// NewChaCha20Key creates a new ChaCha20-Poly1305 key from raw bytes.
// The algorithm parameter should be one of:
//   - string(types.SymmetricChaCha20Poly1305) for standard ChaCha20-Poly1305
//   - string(types.SymmetricXChaCha20Poly1305) for XChaCha20-Poly1305
//
// ChaCha20-Poly1305 uses 256-bit (32-byte) keys only.
// This function validates the key size and makes a copy of the key data
// to prevent external modification.
func NewChaCha20Key(algorithm string, keyData []byte) (types.SymmetricKey, error) {
	keySize := len(keyData) * 8

	// ChaCha20 only supports 256-bit keys
	if keySize != 256 {
		return nil, fmt.Errorf("invalid ChaCha20 key size: %d bits (must be 256)", keySize)
	}

	// Make a copy to prevent external modification
	data := make([]byte, len(keyData))
	copy(data, keyData)

	return &chacha20Key{
		algorithm: algorithm,
		keySize:   keySize,
		keyData:   data,
	}, nil
}

// Verify interface compliance at compile time
var _ types.SymmetricKey = (*chacha20Key)(nil)
