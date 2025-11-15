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

// aesKey implements types.SymmetricKey for AES keys.
type aesKey struct {
	algorithm string
	keySize   int
	keyData   []byte
}

// Algorithm returns the symmetric algorithm identifier.
func (k *aesKey) Algorithm() string {
	return k.algorithm
}

// KeySize returns the key size in bits.
func (k *aesKey) KeySize() int {
	return k.keySize
}

// Raw returns a copy of the raw key bytes to prevent external modification.
func (k *aesKey) Raw() ([]byte, error) {
	// Return a copy to prevent modification
	raw := make([]byte, len(k.keyData))
	copy(raw, k.keyData)
	return raw, nil
}

// NewAESKey creates a new AES key from raw bytes.
// The algorithm parameter should be one of the AES algorithm constants
// (e.g., backend.ALG_AES128_GCM, backend.ALG_AES256_GCM).
//
// This function validates that the key size matches standard AES key sizes
// (128, 192, or 256 bits) and makes a copy of the key data to prevent
// external modification.
func NewAESKey(algorithm string, keyData []byte) (types.SymmetricKey, error) {
	keySize := len(keyData) * 8
	if keySize != 128 && keySize != 192 && keySize != 256 {
		return nil, fmt.Errorf("invalid AES key size: %d bits (must be 128, 192, or 256)", keySize)
	}

	// Make a copy to prevent external modification
	data := make([]byte, len(keyData))
	copy(data, keyData)

	return &aesKey{
		algorithm: algorithm,
		keySize:   keySize,
		keyData:   data,
	}, nil
}

// Verify interface compliance at compile time
var _ types.SymmetricKey = (*aesKey)(nil)
