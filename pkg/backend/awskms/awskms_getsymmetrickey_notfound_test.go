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
	"encoding/json"
	"errors"
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

// TestGetSymmetricKey_NotFound verifies that a genuine KMS NotFoundException
// from DescribeKey is classified as backend.ErrKeyNotFound (go-xkms#808).
func TestGetSymmetricKey_NotFound(t *testing.T) {
	mockClient := &MockKMSClient{
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return nil, &kmstypes.NotFoundException{Message: aws.String("key not found")}
		},
	}
	config := &Config{Region: "us-east-1", KeyStorage: storage.New(), CertStorage: storage.New()}
	b, err := NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:                 "not-found-symmetric-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	metadata := map[string]interface{}{"key_id": "test-key-id"}
	metadataBytes, marshalErr := json.Marshal(metadata)
	require.NoError(t, marshalErr)
	require.NoError(t, storage.SaveKey(context.Background(), config.KeyStorage, attrs.CN, metadataBytes))

	_, err = b.GetSymmetricKey(context.Background(), attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrKeyNotFound), "expected errors.Is(err, backend.ErrKeyNotFound), got %v", err)
}

// TestGetSymmetricKey_RetrievalError verifies that a DescribeKey failure
// that is NOT a NotFoundException (throttling, access denied, a network
// fault) is classified as ErrKeyRetrievalFailed and does NOT satisfy
// errors.Is(err, backend.ErrKeyNotFound) -- go-xkms#808. Collapsing this
// into "not found" would let a get-or-create caller silently replace a KMS
// symmetric key the backend merely failed to reach.
func TestGetSymmetricKey_RetrievalError(t *testing.T) {
	mockClient := &MockKMSClient{
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return nil, &kmstypes.KMSInternalException{Message: aws.String("internal error")}
		},
	}
	config := &Config{Region: "us-east-1", KeyStorage: storage.New(), CertStorage: storage.New()}
	b, err := NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:                 "transient-failure-symmetric-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	metadata := map[string]interface{}{"key_id": "test-key-id"}
	metadataBytes, marshalErr := json.Marshal(metadata)
	require.NoError(t, marshalErr)
	require.NoError(t, storage.SaveKey(context.Background(), config.KeyStorage, attrs.CN, metadataBytes))

	_, err = b.GetSymmetricKey(context.Background(), attrs)
	require.Error(t, err)
	assert.False(t, errors.Is(err, backend.ErrKeyNotFound), "a transient DescribeKey failure must not satisfy errors.Is(err, backend.ErrKeyNotFound), got %v", err)
	assert.True(t, errors.Is(err, ErrKeyRetrievalFailed), "expected errors.Is(err, ErrKeyRetrievalFailed), got %v", err)
}
