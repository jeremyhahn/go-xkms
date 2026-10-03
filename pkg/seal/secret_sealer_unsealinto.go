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

package seal

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// SecretSealer decrypts into caller-supplied memory, so a caller holding the
// plaintext under a memory-protection guarantee never sees it on the heap.
var _ types.UnsealerInto = (*SecretSealer)(nil)

// PlaintextLen reports the exact plaintext size for sealed.
//
// The AEAD is cipher.NewGCMWithRandomNonce, whose Overhead() counts BOTH the
// 12-byte nonce it prepends and the 16-byte tag it appends -- 28 bytes, not the
// 16 a plain GCM would report. The stored envelope splits that nonce back out
// into SealedData.Nonce, so the length is computed over the reassembled blob
// (nonce + ciphertext) rather than over Ciphertext alone. Getting this wrong by
// the nonce width would under-size a caller's buffer by 12 bytes and push the
// decryption onto the heap, which is precisely the failure UnsealInto exists to
// avoid; measured against the AEAD rather than assumed.
func (s *SecretSealer) PlaintextLen(sealed *types.SealedData) (int, error) {
	if sealed == nil {
		return 0, ErrSecretSealerNilSealedData
	}
	if !s.CanSeal() {
		return 0, ErrSecretSealerEmptySecret
	}
	if err := checkEnvelope(sealed); err != nil {
		return 0, err
	}
	gcm, err := s.gcm()
	if err != nil {
		return 0, err
	}
	n := len(sealed.Nonce) + len(sealed.Ciphertext) - gcm.Overhead()
	if n < 0 {
		// Shorter than the overhead it must carry: the envelope is truncated or
		// corrupt. Reported here rather than left to surface as a confusing
		// negative allocation in the caller.
		return 0, types.SealedDataAuthenticationError(fmt.Sprintf(
			"seal: sealed payload is %d bytes, shorter than the %d bytes of AEAD overhead",
			len(sealed.Nonce)+len(sealed.Ciphertext), gcm.Overhead()), nil)
	}
	return n, nil
}

// UnsealInto decrypts sealed into dst, which must have capacity for
// PlaintextLen bytes. It returns dst extended to the plaintext.
//
// Only the CIPHERTEXT is reassembled on the heap here, which is safe: it is the
// encrypted form, and it is what the AEAD needs contiguously. The plaintext is
// written straight into dst by Open and exists nowhere else.
//
// The caller must confirm the result aliases dst; see types.UnsealerInto. Open
// appends, so a dst without the capacity quietly reallocates onto the heap and
// returns that instead, which is indistinguishable from success here.
//
// It authenticates exactly as Unseal does, and reports a failure of the
// sealed data as types.ErrSealedDataAuthentication the same way.
func (s *SecretSealer) UnsealInto(ctx context.Context, dst []byte, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	return s.open(ctx, dst, sealed, opts)
}
