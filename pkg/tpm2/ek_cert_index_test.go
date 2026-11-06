package tpm2

import (
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
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

// TestEKKeyType_ResolvesConfiguredKeyType checks the algorithm is parsed, or
// inferred from the RSA or ECC config present, with the key parameters.
func TestEKKeyType_ResolvesConfiguredKeyType(t *testing.T) {
	rsa, err := ekKeyType(EKConfig{KeyAlgorithm: "RSA", RSAConfig: &store.RSAConfig{KeySize: 2048}})
	require.NoError(t, err)
	assert.Equal(t, x509.RSA, rsa.KeyAlgorithm)
	assert.Equal(t, 2048, rsa.RSAAttributes.KeySize)

	ecc, err := ekKeyType(EKConfig{ECCConfig: &store.ECCConfig{Curve: "P-384"}})
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, ecc.KeyAlgorithm, "inferred from the ECC config")
	assert.Equal(t, elliptic.P384(), ecc.ECCAttributes.Curve)
}

// TestEKKeyType_InvalidConfigFails checks an EK config naming no usable key
// type, or an unknown curve, is an error.
func TestEKKeyType_InvalidConfigFails(t *testing.T) {
	_, err := ekKeyType(EKConfig{})
	assert.Error(t, err, "no algorithm and no RSA or ECC config")

	_, err = ekKeyType(EKConfig{KeyAlgorithm: "ECDSA", ECCConfig: &store.ECCConfig{Curve: "P-999"}})
	assert.Error(t, err, "unknown curve")
}

// TestConfiguredEKKeyType_DefaultsToEKTemplate covers a config that names
// no key size or curve: the EK is created from the default template, so its
// certificate index is the RSA 2048 or the NIST P-256 one.
func TestConfiguredEKKeyType_DefaultsToEKTemplate(t *testing.T) {
	rsa, err := configuredEKKeyType(EKConfig{KeyAlgorithm: "RSA"})
	require.NoError(t, err)
	assert.Equal(t, 2048, rsa.RSAAttributes.KeySize)

	ecc, err := configuredEKKeyType(EKConfig{KeyAlgorithm: "ECDSA"})
	require.NoError(t, err)
	assert.Equal(t, elliptic.P256(), ecc.ECCAttributes.Curve)

	rsa4096, err := configuredEKKeyType(EKConfig{KeyAlgorithm: "RSA", RSAConfig: &store.RSAConfig{KeySize: 4096}})
	require.NoError(t, err)
	assert.Equal(t, 4096, rsa4096.RSAAttributes.KeySize, "a configured key size is kept")

	assert.Equal(t, tpm2.TPMHandle(ekCertIndexECCP256),
		configuredEKCertIndex(EKConfig{CertHandle: ekCertIndexRSA2048, KeyAlgorithm: "ECDSA"}))
}

func TestConfiguredEKKeyType_InvalidConfigFails(t *testing.T) {
	_, err := configuredEKKeyType(EKConfig{})
	assert.Error(t, err, "no algorithm and no RSA or ECC config")

	_, err = configuredEKKeyType(EKConfig{KeyAlgorithm: "ECDSA", ECCConfig: &store.ECCConfig{Curve: "P-999"}})
	assert.Error(t, err, "unknown curve")
}

// TestConfiguredEKCertIndex_FollowsConfiguredKeyType checks the index the EK
// certificate is looked for at, before the EK exists, is the one the write
// path (ekCertIndex) resolves for the configured key type.
func TestConfiguredEKCertIndex_FollowsConfiguredKeyType(t *testing.T) {
	ecc := EKConfig{
		CertHandle:   ekCertIndexRSA2048,
		KeyAlgorithm: x509.ECDSA.String(),
		ECCConfig:    &store.ECCConfig{Curve: "P-256"},
	}
	assert.Equal(t, tpm2.TPMHandle(ekCertIndexECCP256), configuredEKCertIndex(ecc))

	rsa := EKConfig{
		CertHandle:   ekCertIndexRSA2048,
		KeyAlgorithm: x509.RSA.String(),
		RSAConfig:    &store.RSAConfig{KeySize: 2048},
	}
	assert.Equal(t, tpm2.TPMHandle(ekCertIndexRSA2048), configuredEKCertIndex(rsa))
}

// TestConfiguredEKCertIndex_UnresolvedKeyTypeKeepsConfigured checks a key
// type without a TCG index, or one that does not parse, keeps the configured
// index, where a manufacturer may still have provisioned a certificate.
func TestConfiguredEKCertIndex_UnresolvedKeyTypeKeepsConfigured(t *testing.T) {
	rsa4096 := EKConfig{
		CertHandle:   ekCertIndexRSA2048,
		KeyAlgorithm: x509.RSA.String(),
		RSAConfig:    &store.RSAConfig{KeySize: 4096},
	}
	assert.Equal(t, tpm2.TPMHandle(ekCertIndexRSA2048), configuredEKCertIndex(rsa4096))

	unparsed := EKConfig{CertHandle: ekCertIndexRSA2048}
	assert.Equal(t, tpm2.TPMHandle(ekCertIndexRSA2048), configuredEKCertIndex(unparsed))
}
