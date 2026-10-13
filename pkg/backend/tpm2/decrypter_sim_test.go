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

//go:build tpm_simulator

package tpm2

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestDecrypter_RSAOAEPUnderThePlatformPolicy proves an RSA key under the
// default named policy decrypts RSA-OAEP-SHA-256 through crypto.Decrypter:
// the key is authorized by its own policy session, not left unauthorized.
func TestDecrypter_RSAOAEPUnderThePlatformPolicy(t *testing.T) {
	ctx := context.Background()
	backend, err := NewBackend(&Config{UseSimulator: true, Keys: tpmblobtest.New(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	attrs := &types.KeyAttributes{CN: "oaep", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeEncryption, RSAAttributes: &types.RSAAttributes{KeySize: 2048}}
	_, err = backend.GenerateKey(ctx, attrs)
	require.NoError(t, err)
	assert.Equal(t, types.TPMPolicyPlatform, attrs.TPMPolicy)

	dec, err := backend.Decrypter(ctx, attrs)
	require.NoError(t, err)
	pub := dec.Public().(*rsa.PublicKey)
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte("vault factor secret"), nil)
	require.NoError(t, err)

	pt, err := dec.Decrypt(rand.Reader, ct, &rsa.OAEPOptions{Hash: crypto.SHA256})
	require.NoError(t, err)
	assert.Equal(t, []byte("vault factor secret"), pt)

	// Other schemes are refused, never answered with OAEP-SHA-256.
	_, err = dec.Decrypt(rand.Reader, ct, &rsa.OAEPOptions{Hash: crypto.SHA1})
	assert.ErrorIs(t, err, ErrDecryptionNotSupported)
	_, err = dec.Decrypt(rand.Reader, ct, &rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte("l")})
	assert.ErrorIs(t, err, ErrDecryptionNotSupported)
	_, err = dec.Decrypt(rand.Reader, ct, nil)
	assert.ErrorIs(t, err, ErrDecryptionNotSupported)

	// A tampered ciphertext fails in the TPM.
	ct[0] ^= 0xff
	_, err = dec.Decrypt(rand.Reader, ct, &rsa.OAEPOptions{Hash: crypto.SHA256})
	assert.Error(t, err)
}

// TestDecrypter_ECKeysAgreeInstead proves an EC key offers no decrypter:
// key establishment with it is DeriveKeyECDH.
func TestDecrypter_ECKeysAgreeInstead(t *testing.T) {
	ctx := context.Background()
	backend, err := NewBackend(&Config{UseSimulator: true, Keys: tpmblobtest.New(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	attrs := &types.KeyAttributes{CN: "ec", KeyAlgorithm: x509.ECDSA, KeyType: types.KeyTypeEncryption, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()}}
	_, err = backend.GenerateKey(ctx, attrs)
	require.NoError(t, err)
	_, err = backend.Decrypter(ctx, attrs)
	assert.ErrorIs(t, err, ErrDecryptionNotSupported)
}
