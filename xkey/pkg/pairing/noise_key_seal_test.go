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

package pairing

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// xorTestBarrier is a minimal in-memory NoiseKeyBarrier: it XORs with a fixed
// key, which is reversible, deterministic, and enough to prove the seal/
// unseal round trip and the sealed-marker format without a real qrdb
// barrier's password and strategy plumbing. sealedFail forces Encrypt to
// fail, as a real barrier does when it is sealed.
type xorTestBarrier struct {
	key        byte
	sealedFail bool
}

func (b xorTestBarrier) Encrypt(plaintext []byte) ([]byte, error) {
	if b.sealedFail {
		return nil, errBarrierSealedForTest
	}
	return b.xor(plaintext), nil
}

func (b xorTestBarrier) Decrypt(ciphertext []byte) ([]byte, error) {
	if b.sealedFail {
		return nil, errBarrierSealedForTest
	}
	return b.xor(ciphertext), nil
}

func (b xorTestBarrier) xor(in []byte) []byte {
	out := make([]byte, len(in))
	for i, c := range in {
		out[i] = c ^ b.key
	}
	return out
}

var errBarrierSealedForTest = errors.New("test: barrier sealed")

func TestSealLocalNoiseKey_RoundTripsThroughUnseal(t *testing.T) {
	barrier := xorTestBarrier{key: 0x5A}
	priv := []byte("01234567890123456789012345678901") // 33 bytes, arbitrary

	sealed, err := SealLocalNoiseKey(barrier, priv)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(sealed, NoiseKeySealedPrefix),
		"a sealed value must carry the marker so a reader can tell it apart from legacy plaintext")
	require.True(t, IsSealedNoiseKey(sealed))

	buf, err := UnsealLocalNoiseKey(barrier, sealed)
	require.NoError(t, err)
	defer buf.Destroy()

	require.NoError(t, buf.WithBytes(func(b []byte) error {
		assert.Equal(t, priv, b)
		return nil
	}))
}

func TestSealLocalNoiseKey_NoBarrierIsRefused(t *testing.T) {
	sealed, err := SealLocalNoiseKey(nil, []byte("private-scalar"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseKeySealBarrierRequired)
	assert.Empty(t, sealed, "a refused seal must not return a value that looks usable")
}

func TestSealLocalNoiseKey_EmptyKeyIsRefused(t *testing.T) {
	_, err := SealLocalNoiseKey(xorTestBarrier{key: 0x11}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseKeyEmpty)
}

func TestSealLocalNoiseKey_SealedBarrierFailureIsWrapped(t *testing.T) {
	_, err := SealLocalNoiseKey(xorTestBarrier{sealedFail: true}, []byte("private-scalar"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseKeySealFailed)
	assert.ErrorIs(t, err, errBarrierSealedForTest)
}

func TestUnsealLocalNoiseKey_LegacyPlaintextNeedsNoBarrier(t *testing.T) {
	priv := []byte("legacy-plaintext-private-scalar")
	legacy := base64.StdEncoding.EncodeToString(priv)
	require.False(t, IsSealedNoiseKey(legacy), "the legacy form must not be mistaken for the sealed one")

	buf, err := UnsealLocalNoiseKey(nil, legacy)
	require.NoError(t, err, "reading an existing legacy pairing must not require a barrier")
	defer buf.Destroy()

	require.NoError(t, buf.WithBytes(func(b []byte) error {
		assert.Equal(t, priv, b)
		return nil
	}))
}

func TestUnsealLocalNoiseKey_SealedFormWithoutBarrierIsRefused(t *testing.T) {
	barrier := xorTestBarrier{key: 0x42}
	sealed, err := SealLocalNoiseKey(barrier, []byte("private-scalar-32-bytes-exactly"))
	require.NoError(t, err)

	_, err = UnsealLocalNoiseKey(nil, sealed)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseKeyFormMismatch,
		"a sealed key must never fall back to being read as plaintext")
}

func TestUnsealLocalNoiseKey_LegacyFormWithBarrierIsRefused(t *testing.T) {
	priv := []byte("legacy-plaintext-private-scalar")
	legacy := base64.StdEncoding.EncodeToString(priv)

	barrier := xorTestBarrier{key: 0x42}
	_, err := UnsealLocalNoiseKey(barrier, legacy)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseKeyFormMismatch,
		"a barrier open on this host must not read a legacy plaintext record as-is -- there is no migration; re-pair")
}

func TestUnsealLocalNoiseKey_SealedBarrierFailureIsWrapped(t *testing.T) {
	sealed, err := SealLocalNoiseKey(xorTestBarrier{key: 0x77}, []byte("private-scalar-32-bytes-exactly"))
	require.NoError(t, err)

	_, err = UnsealLocalNoiseKey(xorTestBarrier{sealedFail: true}, sealed)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseKeyUnsealFailed)
	assert.ErrorIs(t, err, errBarrierSealedForTest)
}

func TestUnsealLocalNoiseKey_EmptyIsRefused(t *testing.T) {
	_, err := UnsealLocalNoiseKey(xorTestBarrier{key: 0x01}, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseKeyEmpty)
}

func TestUnsealLocalNoiseKey_CorruptSealedBase64IsRefused(t *testing.T) {
	_, err := UnsealLocalNoiseKey(xorTestBarrier{key: 0x01}, NoiseKeySealedPrefix+"not-valid-base64!!!")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseKeyUnsealFailed)
}

func TestUnsealLocalNoiseKey_CorruptLegacyBase64IsRefused(t *testing.T) {
	_, err := UnsealLocalNoiseKey(nil, "not-valid-base64!!!")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseKeyUnsealFailed)
}

func TestIsSealedNoiseKey(t *testing.T) {
	assert.False(t, IsSealedNoiseKey(""))
	assert.False(t, IsSealedNoiseKey(base64.StdEncoding.EncodeToString([]byte("plaintext"))))
	assert.True(t, IsSealedNoiseKey(NoiseKeySealedPrefix+"YWJj"))
}
