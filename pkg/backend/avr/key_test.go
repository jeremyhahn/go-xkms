// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package avr

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"log/slog"
	"testing"

	tfw "github.com/jeremyhahn/trusted-firmware/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDeviceKeyAcceptsThePointTheElementReturns(t *testing.T) {
	point, pub := testPoint(t)

	key, err := newDeviceKey(point, tfw.SlotDeviceID, DefaultKeyCN)
	require.NoError(t, err)

	assert.True(t, pub.Equal(key.Public()))
	assert.Equal(t, tfw.SlotDeviceID, key.Slot())
	assert.Equal(t, DefaultKeyCN, key.CN())
}

// A point that is not on P-256 is not an identity. Accepting one would give
// every later answer about this device -- its enrolment record, the subject of
// a certificate request -- a value that can verify nothing.
func TestNewDeviceKeyRefusesAPointThatIsNotOnTheCurve(t *testing.T) {
	point := make([]byte, devicePointLen)
	for i := range point {
		point[i] = 0xAA
	}

	key, err := newDeviceKey(point, tfw.SlotDeviceID, DefaultKeyCN)

	assert.Nil(t, key)
	assert.ErrorIs(t, err, ErrInvalidDevicePoint)
}

// The point at infinity is all zeroes on this wire. It is a valid-looking
// 64-byte reply from a slot that holds no key, and it must not become an
// identity.
func TestNewDeviceKeyRefusesTheIdentityPoint(t *testing.T) {
	key, err := newDeviceKey(make([]byte, devicePointLen), tfw.SlotDeviceID, DefaultKeyCN)

	assert.Nil(t, key)
	assert.ErrorIs(t, err, ErrInvalidDevicePoint)
}

func TestNewDeviceKeyRefusesAPointOfTheWrongLength(t *testing.T) {
	for _, n := range []int{0, 32, 63, 65, 128} {
		key, err := newDeviceKey(make([]byte, n), tfw.SlotDeviceID, DefaultKeyCN)

		assert.Nil(t, key, "length %d", n)
		require.ErrorIs(t, err, ErrInvalidDevicePoint, "length %d", n)
		assert.Contains(t, err.Error(), "64", "the expected length belongs in the message")
	}
}

// The handle is deliberately NOT a crypto.Signer. A type that offered Sign and
// failed every call would put the discovery that this device cannot sign at
// the end of a protocol exchange the caller had already committed to; failing
// the assertion puts it at the start, where a negotiation can still act on it.
func TestDeviceKeyIsNotASigner(t *testing.T) {
	point, _ := testPoint(t)
	key, err := newDeviceKey(point, tfw.SlotDeviceID, DefaultKeyCN)
	require.NoError(t, err)

	_, isSigner := crypto.PrivateKey(key).(crypto.Signer)
	assert.False(t, isSigner, "a signer that always fails is worse than no signer")

	_, isDecrypter := crypto.PrivateKey(key).(crypto.Decrypter)
	assert.False(t, isDecrypter)
}

// Two devices hold their identities in the same slot and are not the same key,
// so equality is the public point and not the slot.
func TestDeviceKeyEqualComparesThePoint(t *testing.T) {
	pointA, _ := testPoint(t)
	pointB, _ := testPoint(t)

	a, err := newDeviceKey(pointA, tfw.SlotDeviceID, DefaultKeyCN)
	require.NoError(t, err)
	sameA, err := newDeviceKey(pointA, tfw.SlotDeviceID, "another-name")
	require.NoError(t, err)
	b, err := newDeviceKey(pointB, tfw.SlotDeviceID, DefaultKeyCN)
	require.NoError(t, err)

	assert.True(t, a.Equal(sameA), "the same point in the same slot is the same key")
	assert.False(t, a.Equal(b), "a different device is a different key")
}

func TestDeviceKeyEqualRefusesAnythingElse(t *testing.T) {
	point, pub := testPoint(t)
	key, err := newDeviceKey(point, tfw.SlotDeviceID, DefaultKeyCN)
	require.NoError(t, err)

	assert.False(t, key.Equal(pub))
	assert.False(t, key.Equal(nil))
	assert.False(t, key.Equal(&ecdsa.PrivateKey{}))
}

// TestKeyAttributes_UnknownCryptoTierFailsSafeAndLogs proves that
// keyAttributes does not silently discard AttestLevel's error for a crypto
// tier this host cannot classify: the record still comes back stamped
// Unattested (the safe direction), and the reason is logged rather than lost
// (go-xkms#1347).
//
// hasDeviceKey already refuses to call keyAttributes for an unclassified
// tier through every current caller (ListKeys), so this drives the method
// directly to pin the fallback for any future caller that reaches it without
// that guard.
func TestKeyAttributes_UnknownCryptoTierFailsSafeAndLogs(t *testing.T) {
	var buf bytes.Buffer
	b := &Backend{
		config: testConfig(),
		logger: slog.New(slog.NewTextHandler(&buf, nil)),
		caps:   tfw.Caps{CryptoTier: tfw.CryptoTier(9)},
	}

	attrs := b.keyAttributes()

	assert.Equal(t, types.AttestLevelUnattested, attrs.AttestLevel,
		"an unclassified crypto tier must fail safe to Unattested, never assume a level")
	assert.Contains(t, buf.String(), "device reports a crypto tier this host cannot classify",
		"AttestLevel's error must be logged instead of discarded")
}
