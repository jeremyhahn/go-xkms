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

//go:build awskms

package server

import (
	"bytes"
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestInitializePlatformStore_AWSKMSNotConfiguredFailsClosed proves the
// awskms credential strategy fails closed with a typed error when
// backends.awskms is not configured, exactly like tpm2's equivalent check
// -- never a silent skip.
func TestInitializePlatformStore_AWSKMSNotConfiguredFailsClosed(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig("awskms"))
	// Backends.AWSKMS left nil.

	err := s.initializePlatformStore()
	require.Error(t, err)
	assert.Nil(t, s.platformStore)

	var unavailableErr *ErrPlatformStoreStrategyUnavailable
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "awskms", unavailableErr.Strategy)
}

// TestBuildAWSKMSPlatformSealer_RoundTripViaMockClient proves the reusable
// machinery buildAWSKMSPlatformSealer composes -- sealKeyAttributesFor,
// ensureSealKey (seal_strategies.go, shared with the barrier's own awskms
// strategy) and fixedKeyAttrsSealer -- seals and unseals correctly against
// an AWS KMS backend, using the SAME mock KMS client
// (awskms.MockKMSClient) that package's own sealer tests use
// (pkg/backend/awskms/sealer_test.go's TestSealUnseal_Success). It exercises
// the composition directly, rather than buildAWSKMSPlatformSealer itself,
// because that function always dials ambient AWS credentials via
// awskms.NewBackend and has no seam for a test client -- proving ambient
// authentication itself is awskms.NewBackend's own test suite's job, not
// this one's.
func TestBuildAWSKMSPlatformSealer_RoundTripViaMockClient(t *testing.T) {
	plaintext := []byte("platform-store secret sealed via AWS KMS")
	ciphertext := []byte("mock-ciphertext-blob")

	mockClient := &awskms.MockKMSClient{
		EncryptFunc: func(_ context.Context, _ *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
			return &kms.EncryptOutput{CiphertextBlob: ciphertext, KeyId: aws.String("test-key-id")}, nil
		},
		DecryptFunc: func(_ context.Context, params *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			if !bytes.Equal(params.CiphertextBlob, ciphertext) {
				return nil, assert.AnError
			}
			return &kms.DecryptOutput{Plaintext: plaintext, KeyId: aws.String("test-key-id")}, nil
		},
		DescribeKeyFunc: func(_ context.Context, _ *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String("test-key-id")}}, nil
		},
	}

	backend, err := awskms.NewBackendWithClient(&awskms.Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, mockClient)
	require.NoError(t, err)

	s := newMinimalServer(t, &config.Config{})
	keyAttrs := sealKeyAttributesFor(types.StoreAWSKMS)
	require.NoError(t, s.ensureSealKey(seal.StrategyAWSKMS, backend, keyAttrs))

	sealer := &fixedKeyAttrsSealer{inner: backend, attrs: keyAttrs}
	assert.True(t, sealer.CanSeal())

	ctx := context.Background()
	sealed, err := sealer.Seal(ctx, plaintext, nil)
	require.NoError(t, err)
	require.NotNil(t, sealed)
	assert.Equal(t, ciphertext, sealed.Ciphertext)

	got, err := sealer.Unseal(ctx, sealed, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}
