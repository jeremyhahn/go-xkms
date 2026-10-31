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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetKeyParameters_RSAKeySize pins that the requested RSA modulus size
// reaches CreateKeyParameters.KeySize, and that a request without RSA
// attributes keeps the 2048-bit default (go-xkms#1757).
func TestGetKeyParameters_RSAKeySize(t *testing.T) {
	tests := []struct {
		name  string
		attrs *types.RSAAttributes
		want  int32
	}{
		{name: "nil attributes default to 2048", attrs: nil, want: 2048},
		{name: "zero size defaults to 2048", attrs: &types.RSAAttributes{}, want: 2048},
		{name: "2048", attrs: &types.RSAAttributes{KeySize: types.RSAKeySize2048}, want: 2048},
		{name: "3072", attrs: &types.RSAAttributes{KeySize: types.RSAKeySize3072}, want: 3072},
		{name: "4096", attrs: &types.RSAAttributes{KeySize: types.RSAKeySize4096}, want: 4096},
	}
	b := &Backend{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := b.getKeyParameters(&types.KeyAttributes{KeyAlgorithm: x509.RSA, RSAAttributes: tt.attrs})
			require.NoError(t, err)
			require.NotNil(t, params.Kty)
			assert.Equal(t, azkeys.KeyTypeRSA, *params.Kty)
			require.NotNil(t, params.KeySize)
			assert.Equal(t, tt.want, *params.KeySize)
			assert.Nil(t, params.Curve, "an RSA request must not carry a curve")
		})
	}
}

// TestGetKeyParameters_ECCCurve pins that the requested NIST curve reaches
// CreateKeyParameters.Curve, and that a request without ECC attributes keeps
// the P-256 default (go-xkms#1757).
func TestGetKeyParameters_ECCCurve(t *testing.T) {
	tests := []struct {
		name  string
		attrs *types.ECCAttributes
		want  azkeys.CurveName
	}{
		{name: "nil attributes default to P-256", attrs: nil, want: azkeys.CurveNameP256},
		{name: "nil curve defaults to P-256", attrs: &types.ECCAttributes{}, want: azkeys.CurveNameP256},
		{name: "P-256", attrs: &types.ECCAttributes{Curve: elliptic.P256()}, want: azkeys.CurveNameP256},
		{name: "P-384", attrs: &types.ECCAttributes{Curve: elliptic.P384()}, want: azkeys.CurveNameP384},
		{name: "P-521", attrs: &types.ECCAttributes{Curve: elliptic.P521()}, want: azkeys.CurveNameP521},
	}
	b := &Backend{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := b.getKeyParameters(&types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: tt.attrs})
			require.NoError(t, err)
			require.NotNil(t, params.Kty)
			assert.Equal(t, azkeys.KeyTypeEC, *params.Kty)
			require.NotNil(t, params.Curve)
			assert.Equal(t, tt.want, *params.Curve)
			assert.Nil(t, params.KeySize, "an EC request must not carry a key size")
		})
	}
}

// TestGetKeyParameters_RejectsUnsupportedSizeAndCurve pins that a size or
// curve Key Vault does not create is refused with a typed error rather than
// silently replaced by the default.
func TestGetKeyParameters_RejectsUnsupportedSizeAndCurve(t *testing.T) {
	tests := []struct {
		name    string
		attrs   *types.KeyAttributes
		wantErr error
	}{
		{
			name:    "RSA 1024",
			attrs:   &types.KeyAttributes{KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: 1024}},
			wantErr: ErrInvalidKeySize,
		},
		{
			name:    "RSA 8192",
			attrs:   &types.KeyAttributes{KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: 8192}},
			wantErr: ErrInvalidKeySize,
		},
		{
			name:    "P-224",
			attrs:   &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P224()}},
			wantErr: ErrInvalidCurve,
		},
		{
			name:    "Ed25519",
			attrs:   &types.KeyAttributes{KeyAlgorithm: x509.Ed25519},
			wantErr: ErrUnsupportedKeyType,
		},
	}
	b := &Backend{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := b.getKeyParameters(tt.attrs)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestCreateKey_HonorsRequestedSizeAndCurve drives CreateKey through the mock
// Key Vault client and checks the created key's public half, so a request for
// RSA-3072 or P-384 yields exactly that key (go-xkms#1757).
func TestCreateKey_HonorsRequestedSizeAndCurve(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, NewMockKeyVaultClient())
	require.NoError(t, err)

	rsaAttrs := &types.KeyAttributes{
		CN:            "rsa-3072",
		KeyType:       backend.KEY_TYPE_SIGNING,
		StoreType:     backend.STORE_AZUREKV,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: types.RSAKeySize3072},
	}
	_, err = b.CreateKey(rsaAttrs)
	require.NoError(t, err)
	signer, err := b.Signer(context.Background(), rsaAttrs)
	require.NoError(t, err)
	rsaPub, ok := signer.Public().(*rsa.PublicKey)
	require.True(t, ok, "an RSA key's signer must report an *rsa.PublicKey")
	assert.Equal(t, 3072, rsaPub.N.BitLen())

	ecAttrs := &types.KeyAttributes{
		CN:            "ec-p384",
		KeyType:       backend.KEY_TYPE_SIGNING,
		StoreType:     backend.STORE_AZUREKV,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()},
	}
	_, err = b.CreateKey(ecAttrs)
	require.NoError(t, err)
	signer, err = b.Signer(context.Background(), ecAttrs)
	require.NoError(t, err)
	ecPub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok, "an ECDSA key's signer must report an *ecdsa.PublicKey")
	assert.Equal(t, elliptic.P384(), ecPub.Curve)
}

// TestCreateKey_UnsupportedSizeNeverReachesKeyVault pins that a refused size
// fails before any CreateKey call, so no default-sized key is created in its
// place.
func TestCreateKey_UnsupportedSizeNeverReachesKeyVault(t *testing.T) {
	client := NewMockKeyVaultClient()
	b, err := NewBackendWithClient(&Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, client)
	require.NoError(t, err)

	_, err = b.CreateKey(&types.KeyAttributes{
		CN:            "rsa-1024",
		KeyType:       backend.KEY_TYPE_SIGNING,
		StoreType:     backend.STORE_AZUREKV,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 1024},
	})
	require.ErrorIs(t, err, ErrInvalidKeySize)
	assert.Zero(t, client.CreateKeyCallCount("rsa-1024"))
}

// TestCapabilities_MatchKeyParameterTables pins that Capabilities advertises
// exactly the RSA sizes and curves getKeyParameters creates, and that every
// advertised one is accepted.
func TestCapabilities_MatchKeyParameterTables(t *testing.T) {
	b := &Backend{}
	algorithms := b.Capabilities().KeyAlgorithms

	assert.Equal(t, []int{types.RSAKeySize2048, types.RSAKeySize3072, types.RSAKeySize4096}, algorithms.RSAKeySizes)
	assert.Equal(t, []string{"P-256", "P-384", "P-521"}, algorithms.ECDSACurves)

	for _, size := range algorithms.RSAKeySizes {
		_, err := b.getKeyParameters(&types.KeyAttributes{KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: size}})
		assert.NoError(t, err, "advertised RSA size %d must be creatable", size)
	}
	curves := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}
	for _, name := range algorithms.ECDSACurves {
		curve, ok := curves[name]
		require.True(t, ok, "unexpected advertised curve %s", name)
		_, err := b.getKeyParameters(&types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: curve}})
		assert.NoError(t, err, "advertised curve %s must be creatable", name)
	}
}
