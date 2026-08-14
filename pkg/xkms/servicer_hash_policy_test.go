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

package xkms

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestSign_RefusesWeakHashRatherThanDowngrading is the regression guard for the
// silent-downgrade failure mode. The service layer used to answer any hash name
// it could not resolve with SHA-256, so a caller that asked to sign with MD5 or
// SHA-1 received a valid SHA-256 signature and CKR-style success — the
// signature was over a digest the caller never chose, and nothing in the
// response said so. A refused hash must produce a typed error.
func TestSign_RefusesWeakHashRatherThanDowngrading(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "weak-hash-sign-key",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	for _, hash := range []string{"MD5", "SHA-1", "MD4", "RIPEMD-160", "not-a-hash"} {
		t.Run(hash, func(t *testing.T) {
			resp, err := svc.Sign(context.Background(), &transport.SignRequest{
				Backend: "software",
				KeyID:   "weak-hash-sign-key",
				Data:    []byte("payload"),
				Hash:    hash,
			})
			require.Error(t, err, "a refused hash must not produce a signature")
			assert.ErrorIs(t, err, ErrInvalidHashFunction)
			assert.Nil(t, resp)
		})
	}

	// The approved hashes must still sign, so the guard cannot be implemented
	// by rejecting anything unusual.
	for _, hash := range []string{"", "SHA-256", "SHA-384", "SHA-512", "SHA3-256"} {
		t.Run("accepted/"+hash, func(t *testing.T) {
			resp, err := svc.Sign(context.Background(), &transport.SignRequest{
				Backend: "software",
				KeyID:   "weak-hash-sign-key",
				Data:    []byte("payload"),
				Hash:    hash,
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.NotEmpty(t, resp.Signature)
		})
	}
}

// TestSign_WeakHashUnderPolicy asserts the escape hatch reaches the signing
// path. An operator who set crypto.allow_weak_hashes (and therefore started
// xkmsd with --insecure) must actually be able to produce the legacy signature
// the gap was accepted for; otherwise the compliance gap buys nothing and the
// operator is left with a broken deployment and a weakened posture.
func TestSign_WeakHashUnderPolicy(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "weak-hash-policy-key",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	types.SetAllowWeakHashes(true)
	defer types.SetAllowWeakHashes(false)

	resp, err := svc.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "weak-hash-policy-key",
		Data:    []byte("payload"),
		Hash:    "SHA-1",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Signature)
}

// TestEncryptAsym_SHA1OAEPRejectedUnderPolicy asserts that the RSA-OAEP
// refusal is not the weak-hash policy in disguise. OAEP has no legacy
// ciphertexts in this codebase to read back — the wrap path has always used
// SHA-256 — so the escape hatch that exists for signing does not apply, and
// SHA-1 OAEP stays refused with its own error even with the policy on.
func TestEncryptAsym_SHA1OAEPRejectedUnderPolicy(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "oaep-policy-key",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	types.SetAllowWeakHashes(true)
	defer types.SetAllowWeakHashes(false)

	for _, hash := range []string{"sha1", "SHA-1", "MD5"} {
		t.Run(hash, func(t *testing.T) {
			_, err := svc.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
				Backend:   "software",
				KeyID:     "oaep-policy-key",
				Plaintext: []byte("secret"),
				Hash:      hash,
			})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrWeakOAEPHash,
				"OAEP must refuse a broken digest with its own error regardless of the weak-hash policy")
		})
	}
}

// TestDeriveKeyECDH_ConcatKDFHashes covers the service-layer half of the
// PKCS#11 ECDH fix: the hash-name normalization the module's forwarded names
// pass through must resolve SHA-1, SHA-224 and SHA3-224 to their canonical
// spellings, and must not admit them to HKDF.
func TestDeriveKeyECDH_ConcatKDFHashes(t *testing.T) {
	for name, want := range map[string]string{
		"SHA1": "SHA-1", "sha-1": "SHA-1", "SHA-1": "SHA-1",
		"SHA224": "SHA-224", "SHA-224": "SHA-224",
		"SHA3224": "SHA3-224", "SHA3-224": "SHA3-224",
		"SHA256": "SHA-256", "": "SHA-256",
	} {
		assert.Equal(t, want, parseKDFHash(name), "parseKDFHash(%q)", name)
	}

	// Canonicalizing the name is not the same as approving it: the KDF layer
	// still decides per construction.
	x963 := &types.KDFParams{Algorithm: types.KDFAlgorithmX963, Hash: parseKDFHash("SHA1"), KeyLength: 32}
	_, err := x963.Derive([]byte("shared secret material"))
	require.NoError(t, err, "X9.63 with SHA-1 must derive (PKCS#11 CKD_SHA1_KDF)")

	hkdf := &types.KDFParams{Algorithm: types.KDFAlgorithmHKDF, Hash: parseKDFHash("SHA1"), KeyLength: 32}
	_, err = hkdf.Derive([]byte("shared secret material"))
	assert.ErrorIs(t, err, types.ErrUnsupportedKDFHash, "HKDF with SHA-1 must be refused")
}
