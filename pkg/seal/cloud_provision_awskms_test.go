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

package seal

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newAWSKMSMockBackend builds an *awskms.Backend against a MockKMSClient
// behaving like a fresh AWS account, reusing the backend package's own test
// double (MockKMSClient) rather than a generic fake KeyProvider, so this
// proves the ACTUAL awskms.Backend integrates correctly through
// BuildCloudKMSStrategy (go-xkms#757), not just the generic dispatch already
// covered by cloud_provision_test.go.
//
// DescribeKey always misses. EnsureSealKey's AWS branch pre-seeds
// b.metadata[CN] with {"key_id": CN} before ever calling GetSymmetricKey (see
// EnsureSealKey's doc): that seed makes awskms.Backend.GenerateSymmetricKey's
// own "does metadata already have this CN" guard true on the very first call,
// so it returns ErrKeyAlreadyExists WITHOUT calling CreateKey at all -- a
// pre-existing property of the shared seal-key provisioning recipe this test
// documents (createKeyCalled), not something introduced here. The upshot: the
// symmetric key AWS KMS operations subsequently address is CN itself
// ("xmks-barrier-seal"), not a real KMS key id -- which is why Encrypt/Decrypt
// below must accept that literal KeyId, exactly like this test's mock does.
func newAWSKMSMockBackend(t *testing.T) (backend *awskms.Backend, createKeyCalled *bool) {
	t.Helper()

	keyStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	certStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	called := false
	mock := &awskms.MockKMSClient{
		DescribeKeyFunc: func(_ context.Context, _ *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return nil, errors.New("mock: key not found")
		},
		CreateKeyFunc: func(_ context.Context, _ *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			called = true
			return &kms.CreateKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String("mock-key-id-757")},
			}, nil
		},
		CreateAliasFunc: func(_ context.Context, _ *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
			return &kms.CreateAliasOutput{}, nil
		},
		EncryptFunc: func(_ context.Context, params *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
			ct := append([]byte("sealed:"), params.Plaintext...)
			return &kms.EncryptOutput{CiphertextBlob: ct, KeyId: params.KeyId}, nil
		},
		DecryptFunc: func(_ context.Context, params *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			pt := params.CiphertextBlob[len("sealed:"):]
			return &kms.DecryptOutput{Plaintext: pt, KeyId: aws.String("mock-key-id-757")}, nil
		},
	}

	b, err := awskms.NewBackendWithClient(&awskms.Config{
		Region:      "us-east-1",
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}, mock)
	require.NoError(t, err)
	return b, &called
}

// TestBuildCloudKMSStrategy_AWSKMSBackend_InitSealUnseal proves the shared
// composition path (BuildCloudKMSStrategy -> EnsureSealKey ->
// NewCloudKMSStrategy) against the real *awskms.Backend round trips: init
// (seal-key provisioning on first use, idempotent -- see newAWSKMSMockBackend
// for why CreateKey itself is not called on this path), seal, and unseal.
func TestBuildCloudKMSStrategy_AWSKMSBackend_InitSealUnseal(t *testing.T) {
	backend, createKeyCalled := newAWSKMSMockBackend(t)
	defer func() { _ = backend.Close() }()

	ctx := context.Background()
	strategy, err := BuildCloudKMSStrategy(ctx, StrategyAWSKMS, types.StoreAWSKMS, backend)
	require.NoError(t, err)
	require.NotNil(t, strategy)
	require.True(t, strategy.Available())
	require.True(t, strategy.HardwareBacked())
	require.False(t, *createKeyCalled,
		"CreateKey is not reached: the metadata seed already satisfies GenerateSymmetricKey's exists check")

	rootKey := []byte("0123456789abcdef0123456789abcdef")
	sealed, err := strategy.SealRootKey(ctx, rootKey, Credentials{})
	require.NoError(t, err)
	require.NotNil(t, sealed)
	require.Equal(t, StrategyAWSKMS, sealed.Strategy)

	unsealed, err := strategy.UnsealRootKey(ctx, sealed, Credentials{})
	require.NoError(t, err)
	require.Equal(t, rootKey, unsealed)
}

// TestBuildCloudKMSStrategy_AWSKMSBackend_MissingCredentials proves that a
// backend which cannot reach AWS KMS at all (Encrypt fails, simulating
// missing/invalid credentials) surfaces a real error from SealRootKey.
// BuildCloudKMSStrategy itself still succeeds: EnsureSealKey's AWS branch
// resolves the seal key from its own metadata seed without ever calling AWS
// (see newAWSKMSMockBackend), so a credential failure is reachable only once
// an actual Encrypt/Decrypt call is attempted -- exactly what this test
// exercises.
func TestBuildCloudKMSStrategy_AWSKMSBackend_MissingCredentials(t *testing.T) {
	keyStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	certStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	credErr := errors.New("mock: NoCredentialProviders: no valid providers in chain")
	mock := &awskms.MockKMSClient{
		DescribeKeyFunc: func(_ context.Context, _ *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return nil, credErr
		},
		EncryptFunc: func(_ context.Context, _ *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
			return nil, credErr
		},
	}

	backend, err := awskms.NewBackendWithClient(&awskms.Config{
		Region:      "us-east-1",
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}, mock)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	ctx := context.Background()
	strategy, err := BuildCloudKMSStrategy(ctx, StrategyAWSKMS, types.StoreAWSKMS, backend)
	require.NoError(t, err)

	_, err = strategy.SealRootKey(ctx, []byte("0123456789abcdef0123456789abcdef"), Credentials{})
	require.Error(t, err)
}
