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
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSizesMatchFIPS203 pins the parameter set's published lengths.
//
// These are the numbers an application marshals against, and getting one wrong
// would not fail a round-trip test inside this package -- both ends would agree
// on the same wrong size -- but would break every peer and every stored key.
// FIPS 203 Table 2 gives ML-KEM-512 an 800-byte encapsulation key, a 1632-byte
// decapsulation key and a 768-byte ciphertext, with a 32-byte shared secret.
func TestSizesMatchFIPS203(t *testing.T) {
	assert.Equal(t, 800, PublicKeySize, "ML-KEM-512 encapsulation key is 800 bytes")
	assert.Equal(t, 768, CiphertextSize, "ML-KEM-512 ciphertext is 768 bytes")
	assert.Equal(t, 32, SharedSecretSize, "ML-KEM shared secret is 32 bytes")
	assert.Equal(t, 64, SeedSize, "FIPS 203 key generation takes d || z, 32 bytes each")

	kem, err := New()
	require.NoError(t, err)
	defer kem.Clean()

	publicKey, err := kem.GenerateKeyPair()
	require.NoError(t, err)
	assert.Len(t, publicKey, PublicKeySize)
	assert.Len(t, kem.ExportSecretKey(), SeedSize)
}

// TestEncapsulateDecapsulateRoundTrip is the KEM's defining property: the
// secret the sender derives is the secret the recipient recovers.
func TestEncapsulateDecapsulateRoundTrip(t *testing.T) {
	recipient, err := New()
	require.NoError(t, err)
	defer recipient.Clean()

	recipientPublic, err := recipient.GenerateKeyPair()
	require.NoError(t, err)

	sender, err := New()
	require.NoError(t, err)
	defer sender.Clean()

	ciphertext, senderSecret, err := sender.Encapsulate(recipientPublic)
	require.NoError(t, err)
	assert.Len(t, ciphertext, CiphertextSize)
	assert.Len(t, senderSecret, SharedSecretSize)

	recipientSecret, err := recipient.Decapsulate(ciphertext)
	require.NoError(t, err)

	assert.Equal(t, senderSecret, recipientSecret,
		"both parties must derive the same shared secret")
	assert.NotEqual(t, make([]byte, SharedSecretSize), recipientSecret,
		"an all-zero shared secret would mean nothing was derived at all")
}

// TestSeedReconstructsTheSameKey covers the property the PKCS#11 module depends
// on: it stores only the 64-byte seed in a private key object's CKA_VALUE and
// rebuilds the key through Create on every later use. If that rebuild produced a
// different key, every persisted ML-KEM-512 key would decapsulate to garbage.
func TestSeedReconstructsTheSameKey(t *testing.T) {
	original, err := New()
	require.NoError(t, err)
	defer original.Clean()

	originalPublic, err := original.GenerateKeyPair()
	require.NoError(t, err)
	seed := original.ExportSecretKey()

	restored, err := Create(seed)
	require.NoError(t, err)
	defer restored.Clean()

	restoredPublic, err := restored.GenerateKeyPair()
	require.NoError(t, err)
	assert.Equal(t, originalPublic, restoredPublic,
		"the same seed must derive the same encapsulation key")

	// The restored key must also actually decapsulate for the original's public
	// key, which comparing the encoded public keys alone does not prove.
	sender, err := New()
	require.NoError(t, err)
	defer sender.Clean()

	ciphertext, senderSecret, err := sender.Encapsulate(originalPublic)
	require.NoError(t, err)

	restoredSecret, err := restored.Decapsulate(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, senderSecret, restoredSecret,
		"a key rebuilt from its seed must decapsulate what its public key encapsulated")
}

// TestDeterministicFromSeed proves key generation is a pure function of the
// seed, which is what makes the seed a complete representation of the key.
func TestDeterministicFromSeed(t *testing.T) {
	seed := make([]byte, SeedSize)
	_, err := io.ReadFull(rand.Reader, seed)
	require.NoError(t, err)

	first, err := Create(seed)
	require.NoError(t, err)
	defer first.Clean()

	second, err := Create(seed)
	require.NoError(t, err)
	defer second.Clean()

	firstPublic, err := first.GenerateKeyPair()
	require.NoError(t, err)
	secondPublic, err := second.GenerateKeyPair()
	require.NoError(t, err)

	assert.Equal(t, firstPublic, secondPublic)
	assert.Equal(t, first.ExportSecretKey(), second.ExportSecretKey())
}

// TestDistinctKeysDeriveDistinctSecrets guards against a wrapper that ignored
// the recipient's key -- which would let every round-trip test above pass while
// giving every party the same secret.
func TestDistinctKeysDeriveDistinctSecrets(t *testing.T) {
	first, err := New()
	require.NoError(t, err)
	defer first.Clean()

	second, err := New()
	require.NoError(t, err)
	defer second.Clean()

	firstPublic, err := first.GenerateKeyPair()
	require.NoError(t, err)
	secondPublic, err := second.GenerateKeyPair()
	require.NoError(t, err)

	assert.NotEqual(t, firstPublic, secondPublic, "two generated keys must differ")

	sender, err := New()
	require.NoError(t, err)
	defer sender.Clean()

	_, firstSecret, err := sender.Encapsulate(firstPublic)
	require.NoError(t, err)
	_, secondSecret, err := sender.Encapsulate(secondPublic)
	require.NoError(t, err)

	assert.NotEqual(t, firstSecret, secondSecret,
		"encapsulating to different recipients must derive different secrets")
}

// TestDecapsulateWrongCiphertextIsImplicitRejection documents FIPS 203's
// implicit rejection rule.
//
// A well-formed ciphertext that was not produced for this key does not fail:
// the specification requires decapsulation to return a deterministic
// pseudo-random secret derived from the private key, so that an attacker cannot
// distinguish a malformed ciphertext from a valid one by observing an error.
// The secret must be wrong, deterministic, and not an error -- all three.
func TestDecapsulateWrongCiphertextIsImplicitRejection(t *testing.T) {
	recipient, err := New()
	require.NoError(t, err)
	defer recipient.Clean()

	recipientPublic, err := recipient.GenerateKeyPair()
	require.NoError(t, err)

	other, err := New()
	require.NoError(t, err)
	defer other.Clean()
	otherPublic, err := other.GenerateKeyPair()
	require.NoError(t, err)

	sender, err := New()
	require.NoError(t, err)
	defer sender.Clean()

	// A ciphertext addressed to somebody else, so it is structurally valid.
	foreignCiphertext, foreignSecret, err := sender.Encapsulate(otherPublic)
	require.NoError(t, err)

	rejected, err := recipient.Decapsulate(foreignCiphertext)
	require.NoError(t, err, "implicit rejection returns a secret, never an error")
	assert.Len(t, rejected, SharedSecretSize)
	assert.NotEqual(t, foreignSecret, rejected,
		"decapsulating another party's ciphertext must not recover their secret")

	again, err := recipient.Decapsulate(foreignCiphertext)
	require.NoError(t, err)
	assert.Equal(t, rejected, again, "implicit rejection must be deterministic")

	// And the same ciphertext under the key it was made for still works, so the
	// rejection above is about the key and not about the ciphertext being broken.
	recovered, err := other.Decapsulate(foreignCiphertext)
	require.NoError(t, err)
	assert.Equal(t, foreignSecret, recovered)
	_ = recipientPublic
}

// TestBadInput covers the error paths.
func TestBadInput(t *testing.T) {
	kem, err := New()
	require.NoError(t, err)
	defer kem.Clean()

	t.Run("a seed of the wrong length is refused", func(t *testing.T) {
		for _, size := range []int{0, 1, SeedSize - 1, SeedSize + 1, 32} {
			_, err := Create(make([]byte, size))
			assert.ErrorIs(t, err, ErrInvalidSeed, "seed size %d must be refused", size)
		}
	})

	t.Run("a public key of the wrong length is refused", func(t *testing.T) {
		for _, size := range []int{0, 1, PublicKeySize - 1, PublicKeySize + 1, 1184} {
			_, _, err := kem.Encapsulate(make([]byte, size))
			assert.ErrorIs(t, err, ErrInvalidPublicKey, "public key size %d must be refused", size)
		}
	})

	// 1184 above is the ML-KEM-768 public key size, and 1088 here is its
	// ciphertext size: a caller that mixes parameter sets must be refused rather
	// than silently producing a secret from truncated input.
	t.Run("a ciphertext of the wrong length is refused", func(t *testing.T) {
		for _, size := range []int{0, 1, CiphertextSize - 1, CiphertextSize + 1, 1088} {
			_, err := kem.Decapsulate(make([]byte, size))
			assert.ErrorIs(t, err, ErrInvalidCiphertext, "ciphertext size %d must be refused", size)
		}
	})

	t.Run("a cleaned instance refuses every operation", func(t *testing.T) {
		spent, err := New()
		require.NoError(t, err)
		publicKey, err := spent.GenerateKeyPair()
		require.NoError(t, err)
		spent.Clean()

		_, err = spent.GenerateKeyPair()
		assert.ErrorIs(t, err, ErrNotInitialized)

		_, _, err = spent.Encapsulate(publicKey)
		assert.ErrorIs(t, err, ErrNotInitialized)

		_, err = spent.Decapsulate(make([]byte, CiphertextSize))
		assert.ErrorIs(t, err, ErrNotInitialized)

		assert.Nil(t, spent.ExportSecretKey())
	})
}

// TestCleanDestroysTheSeed checks that Clean actually erases the key material
// rather than only dropping the reference, since the caller may still hold the
// slice it was built from. The seed lives in an enclave, so "erased" is
// observable as the instance no longer being able to produce it.
func TestCleanDestroysTheSeed(t *testing.T) {
	seed := make([]byte, SeedSize)
	_, err := io.ReadFull(rand.Reader, seed)
	require.NoError(t, err)

	kem, err := Create(seed)
	require.NoError(t, err)

	held := kem.ExportSecretKey()
	require.Equal(t, seed, held,
		"the instance must hold the seed it was created from")
	require.False(t, bytes.Equal(held, make([]byte, SeedSize)),
		"the fixture seed must not be all zeroes, or this test proves nothing")

	kem.Clean()

	assert.Nil(t, kem.seed,
		"Clean must destroy the enclave holding the seed")
	assert.Nil(t, kem.ExportSecretKey(),
		"a cleaned instance must not be able to produce the seed again")
	assert.NotEqual(t, make([]byte, SeedSize), seed,
		"Clean must not reach back into the caller's own slice")
}

// TestDetails covers the metadata accessors.
func TestDetails(t *testing.T) {
	kem, err := New()
	require.NoError(t, err)
	defer kem.Clean()

	details := kem.Details()
	assert.Equal(t, AlgorithmName, details.Name)
	assert.Equal(t, "ML-KEM-512", details.Name,
		"the name must be the FIPS 203 parameter set, not the Kyber round-3 name")
	assert.Equal(t, PublicKeySize, details.LengthPublicKey)
	assert.Equal(t, SeedSize, details.LengthSecretKey)
	assert.Equal(t, CiphertextSize, details.LengthCiphertext)
	assert.Equal(t, SharedSecretSize, details.LengthSharedSecret)

	assert.Equal(t, PublicKeySize, kem.PublicKeyLength())
	assert.Equal(t, SeedSize, kem.SecretKeyLength())
	assert.Equal(t, CiphertextSize, kem.CiphertextLength())
	assert.Equal(t, SharedSecretSize, kem.SharedSecretLength())
}
