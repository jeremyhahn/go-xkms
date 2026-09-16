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

//go:build awskms

package awskms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestSigner builds a backend and a crypto.Signer over a mock KMS client
// that records the SigningAlgorithm of every Sign call, for asserting that
// kmsSigner.Sign honors the crypto.SignerOpts passed on each call rather than
// an algorithm fixed at Signer construction (H13).
func newTestSigner(t *testing.T, keyAlgorithm x509.PublicKeyAlgorithm) (crypto.Signer, *kmstypes.SigningAlgorithmSpec) {
	t.Helper()

	testRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&testRSAKey.PublicKey)
	require.NoError(t, err)

	var lastAlgorithm kmstypes.SigningAlgorithmSpec
	mockClient := &MockKMSClient{
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				KeyId:     aws.String("test-key-id"),
				PublicKey: pubKeyBytes,
			}, nil
		},
		SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			lastAlgorithm = params.SigningAlgorithm
			return &kms.SignOutput{Signature: []byte("signature")}, nil
		},
	}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "test-signer",
		KeyAlgorithm: keyAlgorithm,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
	}

	signer, err := b.Signer(context.Background(), attrs)
	require.NoError(t, err)

	return signer, &lastAlgorithm
}

// TestKMSSignerSign_HonorsRequestedPadding verifies that a single Signer
// selects RSASSA-PSS or RSASSA-PKCS1-v1_5 per call based on the
// crypto.SignerOpts it is given, instead of the algorithm fixed at
// construction (H13).
func TestKMSSignerSign_HonorsRequestedPadding(t *testing.T) {
	signer, lastAlgorithm := newTestSigner(t, x509.RSA)
	digest := make([]byte, 32)

	sig, err := signer.Sign(rand.Reader, digest, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthAuto})
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
	assert.Equal(t, kmstypes.SigningAlgorithmSpecRsassaPssSha256, *lastAlgorithm)

	sig, err = signer.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
	assert.Equal(t, kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256, *lastAlgorithm)
}

// TestKMSSignerSign_RejectsUnsupportedHash verifies that requesting a hash
// AWS KMS cannot serve (e.g. SHA-1) returns a typed error instead of silently
// signing with the wrong algorithm.
func TestKMSSignerSign_RejectsUnsupportedHash(t *testing.T) {
	signer, _ := newTestSigner(t, x509.RSA)
	digest := make([]byte, 20)

	_, err := signer.Sign(rand.Reader, digest, crypto.SHA1)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAlgorithm)
}

// TestAWSSigningAlgorithm_ECDSA verifies ECDSA hash selection independent of
// padding, across all three hashes AWS KMS supports.
func TestAWSSigningAlgorithm_ECDSA(t *testing.T) {
	tests := []struct {
		hash crypto.Hash
		want kmstypes.SigningAlgorithmSpec
	}{
		{crypto.SHA256, kmstypes.SigningAlgorithmSpecEcdsaSha256},
		{crypto.SHA384, kmstypes.SigningAlgorithmSpecEcdsaSha384},
		{crypto.SHA512, kmstypes.SigningAlgorithmSpecEcdsaSha512},
	}
	for _, tt := range tests {
		got, err := awsSigningAlgorithm(x509.ECDSA, tt.hash)
		require.NoError(t, err)
		assert.Equal(t, tt.want, got)
	}
}

// TestAWSSigningAlgorithm_InvalidInputs verifies that unsupported key
// algorithms and nil options are rejected with typed errors rather than
// silently defaulting.
func TestAWSSigningAlgorithm_InvalidInputs(t *testing.T) {
	_, err := awsSigningAlgorithm(x509.UnknownPublicKeyAlgorithm, crypto.SHA256)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAlgorithm)

	_, err = awsSigningAlgorithm(x509.RSA, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
}
