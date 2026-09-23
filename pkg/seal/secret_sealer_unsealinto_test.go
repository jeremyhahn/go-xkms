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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PlaintextLen has to be EXACT, not an upper bound. A caller sizes locked memory
// from it and cannot grow that memory afterwards, so a result one byte short
// pushes the decryption onto the heap -- silently, because Open appends rather
// than failing.
//
// The arithmetic is easy to get wrong by exactly the nonce width:
// cipher.NewGCMWithRandomNonce reports Overhead() = 28, counting the 12-byte
// nonce it prepends as well as the 16-byte tag, where a plain GCM would report
// 16. Sizes around the block boundary are included because that is where an
// off-by-one in the tag or nonce accounting would show up.
func TestSecretSealer_PlaintextLenIsExact(t *testing.T) {
	ctx := context.Background()
	s, err := NewSecretSealer([]byte("a-test-secret-16-bytes"))
	require.NoError(t, err)

	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 1024} {
		plaintext := make([]byte, n)
		for i := range plaintext {
			plaintext[i] = byte(i)
		}

		sealed, err := s.Seal(ctx, plaintext, nil)
		require.NoError(t, err)

		got, err := s.PlaintextLen(sealed)
		require.NoError(t, err)
		assert.Equal(t, n, got, "PlaintextLen must be exact for a %d-byte plaintext", n)
	}
}

// The whole point of the capability: the plaintext must land in the buffer the
// caller supplied, not in one the AEAD allocated. A buffer sized from
// PlaintextLen must be sufficient, so the result aliases it.
func TestSecretSealer_UnsealIntoLandsInTheCallersBuffer(t *testing.T) {
	ctx := context.Background()
	s, err := NewSecretSealer([]byte("a-test-secret-16-bytes"))
	require.NoError(t, err)

	plaintext := []byte("super-secret-material")
	sealed, err := s.Seal(ctx, plaintext, nil)
	require.NoError(t, err)

	n, err := s.PlaintextLen(sealed)
	require.NoError(t, err)

	buf := make([]byte, n)
	out, err := s.UnsealInto(ctx, buf[:0], sealed, nil)
	require.NoError(t, err)

	assert.Equal(t, plaintext, out, "the plaintext must round-trip")
	require.NotEmpty(t, out)
	assert.Same(t, &buf[0], &out[0],
		"a buffer sized from PlaintextLen must be sufficient, so the result aliases it")
}

// A buffer one byte short reallocates onto the heap instead of failing. This
// pins that behaviour as a measured fact rather than an assumption, because the
// caller's aliasing check is the only thing standing between it and plaintext in
// ordinary memory -- and a future AEAD that errored here instead would make that
// check look redundant when it is not.
func TestSecretSealer_UnsealIntoReallocatesWhenTheBufferIsShort(t *testing.T) {
	ctx := context.Background()
	s, err := NewSecretSealer([]byte("a-test-secret-16-bytes"))
	require.NoError(t, err)

	plaintext := []byte("super-secret-material")
	sealed, err := s.Seal(ctx, plaintext, nil)
	require.NoError(t, err)

	n, err := s.PlaintextLen(sealed)
	require.NoError(t, err)

	short := make([]byte, n-1)
	out, err := s.UnsealInto(ctx, short[:0], sealed, nil)
	require.NoError(t, err, "an undersized destination does NOT fail -- that is the hazard")
	assert.Equal(t, plaintext, out, "it silently succeeds, on the heap")
	assert.NotSame(t, &short[0], &out[0],
		"the result escaped the caller's buffer, which only an aliasing check can detect")
}

// A truncated envelope must be reported rather than producing a negative length
// that a caller would carry into an allocation.
func TestSecretSealer_PlaintextLenRejectsATruncatedEnvelope(t *testing.T) {
	s, err := NewSecretSealer([]byte("a-test-secret-16-bytes"))
	require.NoError(t, err)

	_, err = s.PlaintextLen(&types.SealedData{
		Nonce:      make([]byte, gcmNonceSize),
		Ciphertext: []byte("short"), // far less than the 16-byte tag
	})
	require.Error(t, err)
}

// THE FAIL-CLOSED PROPERTY THE SEALED PATH RESTS ON. compareInEnclave decrypts
// into locked pages and then compares whatever came back; it does NOT
// independently authenticate. So the guarantee that a tampered envelope cannot
// produce a comparable plaintext is entirely the AEAD's, and it is asserted here
// against the REAL SecretSealer rather than a test double.
//
// A double could not carry this property: the whole point is that AES-GCM
// refuses, and a mock that merely returned an error would prove only that the
// mock was written to.
func TestSecretSealer_UnsealIntoFailsClosedOnTamperingAndBadInput(t *testing.T) {
	ctx := context.Background()
	s, err := NewSecretSealer([]byte("a-test-secret-16-bytes"))
	require.NoError(t, err)

	plaintext := []byte("super-secret-material")
	good, err := s.Seal(ctx, plaintext, nil)
	require.NoError(t, err)
	n, err := s.PlaintextLen(good)
	require.NoError(t, err)

	// tamper returns a copy of good with one byte of the named field flipped.
	tamper := func(field string, idx int) *types.SealedData {
		c := &types.SealedData{
			Backend:    good.Backend,
			Nonce:      append([]byte(nil), good.Nonce...),
			Ciphertext: append([]byte(nil), good.Ciphertext...),
		}
		switch field {
		case "ciphertext":
			c.Ciphertext[idx] ^= 0xFF
		case "nonce":
			c.Nonce[idx] ^= 0xFF
		}
		return c
	}

	for _, tc := range []struct {
		name   string
		sealed *types.SealedData
	}{
		{"flipped ciphertext byte", tamper("ciphertext", 0)},
		{"flipped tag byte", tamper("ciphertext", len(good.Ciphertext)-1)},
		{"flipped nonce byte", tamper("nonce", 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, n)
			out, err := s.UnsealInto(ctx, buf[:0], tc.sealed, nil)

			require.Error(t, err, "a tampered envelope must not decrypt")
			assert.Empty(t, out, "and must present no plaintext as success")
			assert.NotEqual(t, plaintext, out)
		})
	}

	// A nonce of the wrong LENGTH is rejected before the AEAD is reached, with a
	// specific message rather than a generic authentication failure — the check
	// exists so a corrupt blob says what is wrong with it.
	t.Run("invalid nonce length", func(t *testing.T) {
		bad := &types.SealedData{
			Backend:    good.Backend,
			Nonce:      good.Nonce[:gcmNonceSize-1],
			Ciphertext: good.Ciphertext,
		}
		_, err := s.UnsealInto(ctx, make([]byte, n)[:0], bad, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nonce")

		_, err = s.PlaintextLen(bad)
		require.Error(t, err, "the length must be refused too, not computed from a bad envelope")
	})

	t.Run("nil envelope", func(t *testing.T) {
		_, err := s.UnsealInto(ctx, make([]byte, n)[:0], nil, nil)
		require.Error(t, err)

		_, err = s.PlaintextLen(nil)
		require.Error(t, err)
	})

	// A sealer with no usable key must refuse rather than attempt anything.
	t.Run("unavailable secret", func(t *testing.T) {
		var unusable *SecretSealer
		require.False(t, unusable.CanSeal())

		_, err := unusable.UnsealInto(ctx, make([]byte, n)[:0], good, nil)
		assert.ErrorIs(t, err, ErrSecretSealerEmptySecret)

		_, err = unusable.PlaintextLen(good)
		assert.ErrorIs(t, err, ErrSecretSealerEmptySecret)
	})

	// The control: the untampered envelope still round-trips, so the assertions
	// above cannot be satisfied by a function that always fails.
	t.Run("untampered still succeeds", func(t *testing.T) {
		buf := make([]byte, n)
		out, err := s.UnsealInto(ctx, buf[:0], good, nil)
		require.NoError(t, err)
		assert.Equal(t, plaintext, out)
	})
}
