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

package tpm2

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the pure-software half of the credential challenge --
// building and naming a challenge without any TPM involved -- so they need
// no simulator and run unconditionally. The device round trip (does a real
// TPM answer what NewCredentialChallenge built) lives in
// credential_challenge_simulator_test.go.

// TestNewCredentialChallenge_Success proves NewCredentialChallenge builds a
// non-empty challenge and a 32-byte secret for both RSA and ECDSA EK public
// keys, entirely in software.
func TestNewCredentialChallenge_Success(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	name := []byte{0x00, 0x0b, 0xde, 0xad, 0xbe, 0xef} // fake SHA-256 TPM2B_NAME-shaped bytes

	challengeRSA, secretRSA, err := NewCredentialChallenge(&rsaKey.PublicKey, name)
	require.NoError(t, err)
	assert.NotEmpty(t, challengeRSA.CredentialBlob)
	assert.NotEmpty(t, challengeRSA.EncryptedSecret)
	assert.Len(t, secretRSA, credentialChallengeSecretSize)

	challengeECC, secretECC, err := NewCredentialChallenge(&ecKey.PublicKey, name)
	require.NoError(t, err)
	assert.NotEmpty(t, challengeECC.CredentialBlob)
	assert.NotEmpty(t, challengeECC.EncryptedSecret)
	assert.Len(t, secretECC, credentialChallengeSecretSize)

	// Two challenges built against the same inputs must not be identical:
	// both the seed (RSA) and the ephemeral key (ECC) are freshly random.
	challengeRSA2, secretRSA2, err := NewCredentialChallenge(&rsaKey.PublicKey, name)
	require.NoError(t, err)
	assert.NotEqual(t, challengeRSA.EncryptedSecret, challengeRSA2.EncryptedSecret)
	assert.NotEqual(t, secretRSA, secretRSA2)
}

// TestNewCredentialChallenge_NilEKPublicKey_Error proves a nil EK public key
// is refused with the typed ErrEKPublicRequired, not a panic or a generic
// error from deep inside the conversion.
func TestNewCredentialChallenge_NilEKPublicKey_Error(t *testing.T) {
	_, _, err := NewCredentialChallenge(nil, []byte{0x00, 0x0b})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEKPublicRequired)
}

// TestNewCredentialChallenge_EmptyActivationKeyName_Error proves an empty
// activationKeyName is refused with the typed ErrActivationKeyNameRequired.
func TestNewCredentialChallenge_EmptyActivationKeyName_Error(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, _, err = NewCredentialChallenge(&rsaKey.PublicKey, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrActivationKeyNameRequired)
}

// TestNewCredentialChallenge_UnsupportedKeyType_Error proves an EK public
// key of a type this package cannot convert to a TPM public area (Ed25519
// is not a TPM 2.0 asymmetric algorithm) is refused with the typed
// ErrCredentialChallenge, not a bare conversion error.
func TestNewCredentialChallenge_UnsupportedKeyType_Error(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, _, err = NewCredentialChallenge(pub, []byte{0x00, 0x0b})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCredentialChallenge)
}

// TestActivationKeyName_Success proves ActivationKeyName computes the same
// Name a TPM would for a marshaled public area, matching tpm2.ObjectName
// directly.
func TestActivationKeyName_Success(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pub, err := publicKeyToTPMPublic(&rsaKey.PublicKey)
	require.NoError(t, err)

	want, err := tpm2.ObjectName(pub)
	require.NoError(t, err)

	got, err := ActivationKeyName(tpm2.Marshal(pub))
	require.NoError(t, err)

	assert.Equal(t, want.Buffer, got)
	assert.NotEmpty(t, got)
}

// TestActivationKeyName_InvalidPublicArea_Error proves garbage bytes that
// cannot be unmarshaled as a TPMT_PUBLIC are refused with the typed
// ErrCredentialChallenge, not a bare unmarshal error.
func TestActivationKeyName_InvalidPublicArea_Error(t *testing.T) {
	_, err := ActivationKeyName([]byte{0x01, 0x02, 0x03})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCredentialChallenge)
}
