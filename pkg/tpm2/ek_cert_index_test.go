package tpm2

import (
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEKCertIndex_FollowsEKKeyType pins the TCG EK Credential Profile v2.1
// §2.2.1.4 low-range indices: a TCG-default configured index is replaced by
// the one the EK's own key type names, whichever default was configured.
func TestEKCertIndex_FollowsEKKeyType(t *testing.T) {
	tests := []struct {
		name  string
		attrs *types.KeyAttributes
		want  tpm2.TPMHandle
	}{
		{
			name:  "RSA 2048",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: 2048}},
			want:  0x01C00002,
		},
		{
			name:  "ECC P-256",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()}},
			want:  0x01C0000A,
		},
		{
			name:  "ECC P-384",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()}},
			want:  0x01C00016,
		},
		{
			name:  "ECC P-521",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P521()}},
			want:  0x01C00018,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ekCertIndex(ekCertIndexRSA2048, tt.attrs)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestEKCertIndex_CustomIndexIsKept checks that an operator-chosen index
// outside the TCG EK certificate set is used as configured.
func TestEKCertIndex_CustomIndexIsKept(t *testing.T) {
	custom := tpm2.TPMHandle(0x01C90000)
	attrs := &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()}}

	got, err := ekCertIndex(custom, attrs)
	require.NoError(t, err)
	assert.Equal(t, custom, got)
}

// TestEKCertIndex_UnmappedKeyTypeFails checks that an EK the profile gives
// no certificate index fails typed instead of landing on the RSA index.
func TestEKCertIndex_UnmappedKeyTypeFails(t *testing.T) {
	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{"RSA 3072", &types.KeyAttributes{KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: 3072}}},
		{"RSA without attributes", &types.KeyAttributes{KeyAlgorithm: x509.RSA}},
		{"ECC P-224", &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P224()}}},
		{"ECC without attributes", &types.KeyAttributes{KeyAlgorithm: x509.ECDSA}},
		{"Ed25519", &types.KeyAttributes{KeyAlgorithm: x509.Ed25519}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ekCertIndex(ekCertIndexRSA2048, tt.attrs)
			assert.ErrorIs(t, err, ErrEKCertKeyType)
		})
	}
}
