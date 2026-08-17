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

package xkms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPivSlotCN mirrors pkg/xkms.PivSlotCN's "piv-<slot>" convention: tests
// only need a stable CN, not the exported helper itself.
func testPivSlotCN(slot PIVSlot) string {
	return "piv-" + string(slot)
}

// setupPIVSigner initializes the PIV manager singleton around a freshly
// generated ECDSA P-256 key registered for slot, wires a resolver that
// always returns the software generator, and returns the signer's public
// key. It resets the PIV manager on test cleanup so tests never leak state
// into each other.
func setupPIVSigner(t *testing.T, slot PIVSlot) crypto.PublicKey {
	t.Helper()
	XKMSResetPIV()
	t.Cleanup(XKMSResetPIV)

	require.NoError(t, InitializePIV(&PIVManagerConfig{}))

	gen := NewSoftwarePIVKeyGenerator()
	signer, err := gen.GeneratePIVKey(slot, "ecdsap256", testPivSlotCN(slot))
	require.NoError(t, err)

	require.NoError(t, SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) {
		return gen, nil
	}))

	return signer.Public()
}

// TestNewPIVCryptoSigner_RequiresPublicKey proves the constructor rejects a
// nil public key rather than building a signer that can never match its
// certificate.
func TestNewPIVCryptoSigner_RequiresPublicKey(t *testing.T) {
	_, err := NewPIVCryptoSigner("software", PIVSlot("9a"), nil)
	require.ErrorIs(t, err, ErrPIVCryptoSignerPublicKeyRequired)
}

// TestPIVCryptoSigner_SignECDSA proves the adapter signs an already-hashed
// digest through SignPIV and that Public() reports the slot's public key.
func TestPIVCryptoSigner_SignECDSA(t *testing.T) {
	pub := setupPIVSigner(t, PIVSlot("9a"))

	signer, err := NewPIVCryptoSigner("software", PIVSlot("9a"), pub)
	require.NoError(t, err)
	assert.Equal(t, pub, signer.Public())

	digest := sha256.Sum256([]byte("tls client auth digest"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, ecdsa.VerifyASN1(ecdsaPub, digest[:], sig), "signature must verify against the slot's public key")
}

// TestPIVCryptoSigner_SignEd25519 proves the Ed25519 path signs the raw
// message it is handed (crypto.Hash(0)), matching Ed25519's crypto.Signer
// convention where the "digest" argument IS the message.
func TestPIVCryptoSigner_SignEd25519(t *testing.T) {
	XKMSResetPIV()
	t.Cleanup(XKMSResetPIV)
	require.NoError(t, InitializePIV(&PIVManagerConfig{}))

	gen := NewSoftwarePIVKeyGenerator()
	signer, err := gen.GeneratePIVKey(PIVSlot("9c"), "ed25519", testPivSlotCN(PIVSlot("9c")))
	require.NoError(t, err)
	require.NoError(t, SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) { return gen, nil }))

	pivSigner, err := NewPIVCryptoSigner("software", PIVSlot("9c"), signer.Public())
	require.NoError(t, err)

	message := []byte("tls raw message for ed25519")
	sig, err := pivSigner.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)

	edPub, ok := signer.Public().(ed25519.PublicKey)
	require.True(t, ok)
	assert.True(t, ed25519.Verify(edPub, message, sig))
}

// TestPIVCryptoSigner_SignPropagatesFailure proves a signing failure (no
// signer available for the slot) surfaces as an error rather than a bad
// signature.
func TestPIVCryptoSigner_SignPropagatesFailure(t *testing.T) {
	XKMSResetPIV()
	t.Cleanup(XKMSResetPIV)
	require.NoError(t, InitializePIV(&PIVManagerConfig{}))

	// No key was ever generated for this slot/CN: the in-memory software
	// generator has nothing to return.
	pivSigner, err := NewPIVCryptoSigner("software", PIVSlot("9d"), &ecdsa.PublicKey{})
	require.NoError(t, err)

	digest := sha512.Sum384([]byte("payload"))
	_, err = pivSigner.Sign(rand.Reader, digest[:], crypto.SHA384)
	require.Error(t, err)
}

// TestPivHashAlgorithmName pins the crypto.Hash to SignPIV hash-name mapping,
// including the nil-opts and unrecognized-hash edge cases.
func TestPivHashAlgorithmName(t *testing.T) {
	tests := []struct {
		name string
		opts crypto.SignerOpts
		want string
	}{
		{"sha256", crypto.SHA256, "sha256"},
		{"sha384", crypto.SHA384, "sha384"},
		{"sha512", crypto.SHA512, "sha512"},
		{"ed25519 zero hash", crypto.Hash(0), ""},
		{"unrecognized hash", crypto.MD5, ""},
		{"nil opts", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, pivHashAlgorithmName(tc.opts))
		})
	}
}
