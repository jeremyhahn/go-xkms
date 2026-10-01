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

//go:build azurekv

package azurekv

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestRawECDSAAlgorithm pins the curve-to-algorithm pairing Key Vault
// enforces and the refusals for a mismatched digest or an unsupported curve.
func TestRawECDSAAlgorithm(t *testing.T) {
	cases := []struct {
		curve     elliptic.Curve
		digestLen int
		want      azkeys.SignatureAlgorithm
		wantErrIs error
	}{
		{curve: elliptic.P256(), digestLen: 32, want: azkeys.SignatureAlgorithmES256},
		{curve: elliptic.P384(), digestLen: 48, want: azkeys.SignatureAlgorithmES384},
		{curve: elliptic.P521(), digestLen: 64, want: azkeys.SignatureAlgorithmES512},
		{curve: elliptic.P256(), digestLen: 48, wantErrIs: ErrRawECDSADigestUnsupported},
		{curve: elliptic.P384(), digestLen: 64, wantErrIs: ErrRawECDSADigestUnsupported},
		{curve: elliptic.P224(), digestLen: 28, wantErrIs: ErrInvalidCurve},
	}
	for _, tc := range cases {
		t.Run(tc.curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			got, err := rawECDSAAlgorithm(&key.PublicKey, tc.digestLen)
			if tc.wantErrIs != nil {
				require.ErrorIs(t, err, tc.wantErrIs)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestSigner_RawECDSA signs a raw digest (crypto.Hash(0), PKCS#11's
// CKM_ECDSA) through the Key Vault signer: a digest of the curve's paired size
// signs and verifies over exactly the supplied bytes, and any other length is
// refused with the typed error before a request is sent.
func TestSigner_RawECDSA(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, NewMockKeyVaultClient())
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:            "raw-ecdsa",
		KeyType:       backend.KEY_TYPE_SIGNING,
		StoreType:     backend.STORE_AZUREKV,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	_, err = b.CreateKey(attrs)
	require.NoError(t, err)

	signer, err := b.Signer(context.Background(), attrs)
	require.NoError(t, err)
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok, "an ECDSA key's signer must report an *ecdsa.PublicKey")

	digest := make([]byte, 32)
	_, err = rand.Read(digest)
	require.NoError(t, err)
	sig, err := signer.Sign(rand.Reader, digest, crypto.Hash(0))
	require.NoError(t, err)
	require.True(t, ecdsa.VerifyASN1(pub, digest, sig), "the raw signature must verify over the supplied digest")

	_, err = signer.Sign(rand.Reader, make([]byte, 48), crypto.Hash(0))
	require.ErrorIs(t, err, ErrRawECDSADigestUnsupported)
}
