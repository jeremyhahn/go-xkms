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

package sealed

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// The guarded delete decrypts into caller-supplied memory, so a sealer used with
// it has to implement types.UnsealerInto. These give the package's test sealers
// that capability, appending into dst exactly as the real one does rather than
// allocating and copying -- a test double that quietly allocated would hide the
// very escape compareInEnclave exists to detect.

var (
	_ types.UnsealerInto = (*mockSealer)(nil)
	_ types.UnsealerInto = randomizingSealer{}
)

// PlaintextLen mirrors mockSealer.Seal, which is a byte-for-byte XOR.
func (m *mockSealer) PlaintextLen(sealed *types.SealedData) (int, error) {
	if m.unsealErr != nil {
		return 0, m.unsealErr
	}
	return len(sealed.Ciphertext), nil
}

// UnsealInto appends the unsealed bytes to dst, mirroring mockSealer.Unseal.
func (m *mockSealer) UnsealInto(_ context.Context, dst []byte, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}
	if m.unsealIntoErr != nil {
		return nil, m.unsealIntoErr
	}
	for _, b := range sealed.Ciphertext {
		dst = append(dst, b^0xFF)
	}
	return dst, nil
}

// PlaintextLen mirrors randomizingSealer.Seal, whose ciphertext is the same
// length as the plaintext.
func (randomizingSealer) PlaintextLen(sealed *types.SealedData) (int, error) {
	return len(sealed.Ciphertext), nil
}

// UnsealInto appends the unsealed bytes to dst, mirroring randomizingSealer.Unseal.
func (randomizingSealer) UnsealInto(_ context.Context, dst []byte, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	for i, b := range sealed.Ciphertext {
		dst = append(dst, b^sealed.Nonce[i%len(sealed.Nonce)])
	}
	return dst, nil
}
