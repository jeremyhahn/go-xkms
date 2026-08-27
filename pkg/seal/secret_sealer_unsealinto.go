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

	"github.com/jeremyhahn/go-xkms/pkg/errs"
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
		return 0, &errs.Message{Msg: "seal: sealed data is nil"}
	}
	if !s.CanSeal() {
		return 0, ErrSecretSealerEmptySecret
	}
	if len(sealed.Nonce) != gcmNonceSize {
		return 0, &errs.Message{Msg: fmt.Sprintf(
			"seal: nonce is %d bytes, want %d", len(sealed.Nonce), gcmNonceSize)}
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
		return 0, &errs.Message{Msg: fmt.Sprintf(
			"seal: sealed payload is %d bytes, shorter than the %d bytes of AEAD overhead",
			len(sealed.Nonce)+len(sealed.Ciphertext), gcm.Overhead())}
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
func (s *SecretSealer) UnsealInto(_ context.Context, dst []byte, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, &errs.Message{Msg: "seal: sealed data is nil"}
	}
	if !s.CanSeal() {
		return nil, ErrSecretSealerEmptySecret
	}
	if len(sealed.Nonce) != gcmNonceSize {
		return nil, &errs.Message{Msg: fmt.Sprintf(
			"seal: nonce is %d bytes, want %d", len(sealed.Nonce), gcmNonceSize)}
	}
	gcm, err := s.gcm()
	if err != nil {
		return nil, err
	}
	// The random-nonce AEAD expects its nonce at the head of the payload rather
	// than passed separately, exactly as Unseal reassembles it.
	blob := make([]byte, 0, len(sealed.Nonce)+len(sealed.Ciphertext))
	blob = append(blob, sealed.Nonce...)
	blob = append(blob, sealed.Ciphertext...)
	return gcm.Open(dst, nil, blob, nil)
}
