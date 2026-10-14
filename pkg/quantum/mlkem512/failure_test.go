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

package mlkem512

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errEntropy is the failure failingReader reports.
var errEntropy = errors.New("entropy source exhausted")

// failingReader is an entropy source that always fails.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errEntropy }

// withFailingEntropy replaces crypto/rand.Reader with a source that always
// fails, restoring it when the test ends. Tests that call it must not run in
// parallel.
func withFailingEntropy(t *testing.T) {
	t.Helper()
	original := rand.Reader
	rand.Reader = failingReader{}
	t.Cleanup(func() { rand.Reader = original })
}

// TestEncapsulateRefusesAnUnnormalisedPublicKey verifies FIPS 203's
// encapsulation key modulus check: a key of the right length whose packed
// coefficients are not reduced mod q is refused rather than used.
func TestEncapsulateRefusesAnUnnormalisedPublicKey(t *testing.T) {
	kem, ok := requireMLKEM(t)
	if !ok {
		return
	}
	defer kem.Clean()

	// Every 12-bit coefficient packed from 0xFF bytes is 4095, above q = 3329.
	malformed := bytes.Repeat([]byte{0xFF}, PublicKeySize)

	ciphertext, sharedSecret, err := kem.Encapsulate(malformed)
	assert.ErrorIs(t, err, ErrInvalidPublicKey)
	assert.Nil(t, ciphertext)
	assert.Nil(t, sharedSecret)
}

// TestExportSecretKeyReturnsNilOnceTheSeedIsDestroyed verifies a live
// instance whose sealed seed has been destroyed exports nothing rather than
// an empty or stale seed.
func TestExportSecretKeyReturnsNilOnceTheSeedIsDestroyed(t *testing.T) {
	kem, ok := requireMLKEM(t)
	if !ok {
		return
	}
	defer kem.Clean()
	require.Len(t, kem.ExportSecretKey(), SeedSize)

	kem.seed.Destroy()

	assert.Nil(t, kem.ExportSecretKey())
}

// TestNewFailsWhenEntropyFails verifies New reports the entropy failure
// instead of deriving a key from an unfilled, all-zero seed.
func TestNewFailsWhenEntropyFails(t *testing.T) {
	if _, ok := requireMLKEM(t); !ok {
		return
	}
	withFailingEntropy(t)

	kem, err := New()
	assert.ErrorIs(t, err, errEntropy)
	assert.Nil(t, kem)
}

// TestEncapsulateFailsWhenEntropyFails verifies Encapsulate reports
// ErrEncapsulationFailed instead of encapsulating with an all-zero seed,
// which would make the shared secret predictable.
func TestEncapsulateFailsWhenEntropyFails(t *testing.T) {
	kem, ok := requireMLKEM(t)
	if !ok {
		return
	}
	defer kem.Clean()
	publicKey, err := kem.GenerateKeyPair()
	require.NoError(t, err)
	withFailingEntropy(t)

	ciphertext, sharedSecret, err := kem.Encapsulate(publicKey)
	assert.ErrorIs(t, err, ErrEncapsulationFailed)
	assert.Nil(t, ciphertext)
	assert.Nil(t, sharedSecret)
}
