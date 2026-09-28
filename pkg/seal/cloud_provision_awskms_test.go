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
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// awsGeneratedKeyID is the AWS-assigned key ID newAWSKMSMockBackend's mock
// CreateKey returns. Every mock operation that receives a KeyId asserts it
// against this value, never against seal.SealKeyCN: go-xkms#839 was exactly
// EnsureSealKey addressing KMS operations with the seal key's CN because a
// pre-seeded metadata entry made GenerateSymmetricKey's "already exists"
// guard skip CreateKey before it ever ran.
const awsGeneratedKeyID = "mock-key-id-757"

// newAWSKMSMockBackend builds an *awskms.Backend against a MockKMSClient
// behaving like a fresh AWS account (no operator-configured Config.KeyID, no
// pre-existing CMK), reusing the backend package's own test double
// (MockKMSClient) rather than a generic fake KeyProvider, so this proves the
// ACTUAL awskms.Backend integrates correctly through BuildCloudKMSStrategy
// (go-xkms#757), not just the generic dispatch already covered by
// cloud_provision_test.go.
//
// DescribeKey only succeeds for awsGeneratedKeyID -- the ID CreateKey hands
// back -- so a call addressed to any other ID (including the CN) fails,
// exactly like a real AWS account where the CN is never a valid KMS key
// identifier. createKeyCalls counts CreateKey invocations so tests can
// assert it runs exactly once per real key, not once per EnsureSealKey call.
func newAWSKMSMockBackend(t *testing.T) (b *awskms.Backend, createKeyCalls *int) {
	t.Helper()

	keyStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	certStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	calls := 0
	mock := &awskms.MockKMSClient{
		DescribeKeyFunc: func(_ context.Context, params *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			keyID := aws.ToString(params.KeyId)
			if keyID != awsGeneratedKeyID {
				return nil, fmt.Errorf("mock: key not found: %q", keyID)
			}
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String(keyID)},
			}, nil
		},
		CreateKeyFunc: func(_ context.Context, _ *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			calls++
			return &kms.CreateKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String(awsGeneratedKeyID)},
			}, nil
		},
		CreateAliasFunc: func(_ context.Context, _ *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
			return &kms.CreateAliasOutput{}, nil
		},
		EncryptFunc: func(_ context.Context, params *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
			keyID := aws.ToString(params.KeyId)
			if keyID != awsGeneratedKeyID {
				return nil, fmt.Errorf("mock: Encrypt called with KeyId %q, want the CreateKey-assigned id %q", keyID, awsGeneratedKeyID)
			}
			ct := append([]byte("sealed:"), params.Plaintext...)
			return &kms.EncryptOutput{CiphertextBlob: ct, KeyId: params.KeyId}, nil
		},
		DecryptFunc: func(_ context.Context, params *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			pt := params.CiphertextBlob[len("sealed:"):]
			return &kms.DecryptOutput{Plaintext: pt, KeyId: aws.String(awsGeneratedKeyID)}, nil
		},
	}

	backend, err := awskms.NewBackendWithClient(&awskms.Config{
		Region:      "us-east-1",
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}, mock)
	require.NoError(t, err)
	return backend, &calls
}

// TestBuildCloudKMSStrategy_AWSKMSBackend_CreatesKeyOnFirstProvisioning
// proves the go-xkms#839 fix: with no operator-configured CMK,
// BuildCloudKMSStrategy's first provisioning calls CreateKey exactly once
// and persists the AWS-assigned key ID, and every subsequent Encrypt/Decrypt
// addresses that real ID -- never seal.SealKeyCN.
func TestBuildCloudKMSStrategy_AWSKMSBackend_CreatesKeyOnFirstProvisioning(t *testing.T) {
	backend, createKeyCalls := newAWSKMSMockBackend(t)
	defer func() { _ = backend.Close() }()

	ctx := context.Background()
	strategy, err := BuildCloudKMSStrategy(ctx, StrategyAWSKMS, types.StoreAWSKMS, backend)
	require.NoError(t, err)
	require.NotNil(t, strategy)
	require.True(t, strategy.Available())
	require.True(t, strategy.HardwareBacked())
	assert.Equal(t, 1, *createKeyCalls, "CreateKey must run once to provision a real CMK")

	rootKey := []byte("0123456789abcdef0123456789abcdef")
	sealed, err := strategy.SealRootKey(ctx, rootKey, Credentials{})
	require.NoError(t, err)
	require.NotNil(t, sealed)
	require.Equal(t, StrategyAWSKMS, sealed.Strategy)

	unsealed, err := strategy.UnsealRootKey(ctx, sealed, Credentials{})
	require.NoError(t, err)
	require.Equal(t, rootKey, unsealed)
}

// TestBuildCloudKMSStrategy_AWSKMSBackend_SecondProvisioningReusesKey proves
// that provisioning the same, still-live backend a second time (e.g. a
// second barrier operation in the same process) resolves the CMK CreateKey
// already created through GetSymmetricKey and does not call CreateKey again.
func TestBuildCloudKMSStrategy_AWSKMSBackend_SecondProvisioningReusesKey(t *testing.T) {
	backend, createKeyCalls := newAWSKMSMockBackend(t)
	defer func() { _ = backend.Close() }()

	ctx := context.Background()
	_, err := BuildCloudKMSStrategy(ctx, StrategyAWSKMS, types.StoreAWSKMS, backend)
	require.NoError(t, err)
	require.Equal(t, 1, *createKeyCalls)

	strategy, err := BuildCloudKMSStrategy(ctx, StrategyAWSKMS, types.StoreAWSKMS, backend)
	require.NoError(t, err)
	require.NotNil(t, strategy)
	assert.Equal(t, 1, *createKeyCalls, "second provisioning must reuse the persisted key, not call CreateKey again")
}

// TestBuildCloudKMSStrategy_AWSKMSBackend_RestartReusesPersistedKey proves
// the go-xkms#839 persistence fix end-to-end: *awskms.Backend keeps no
// in-process key-ID cache (pkg/backend/awskms#839 companion fix), so a
// second Backend built over the SAME storage.Backend as the first --
// simulating a process restart -- must resolve the CMK the first Backend's
// CreateKey already created, through EnsureSealKey/GetSymmetricKey, without
// CreateKey running again. Without that persistence, EnsureSealKey would
// create ANOTHER CMK on the second Backend (since it, too, sees no metadata
// for the CN), orphaning the first and leaving data sealed under the first
// CMK unreadable -- the failure the go-xkms coordinator flagged this fix for.
func TestBuildCloudKMSStrategy_AWSKMSBackend_RestartReusesPersistedKey(t *testing.T) {
	keyStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	certStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	createKeyCalls := 0
	newMock := func() *awskms.MockKMSClient {
		return &awskms.MockKMSClient{
			DescribeKeyFunc: func(_ context.Context, params *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
				keyID := aws.ToString(params.KeyId)
				if keyID != awsGeneratedKeyID {
					return nil, fmt.Errorf("mock: key not found: %q", keyID)
				}
				return &kms.DescribeKeyOutput{
					KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String(keyID)},
				}, nil
			},
			CreateKeyFunc: func(_ context.Context, _ *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
				createKeyCalls++
				return &kms.CreateKeyOutput{
					KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String(awsGeneratedKeyID)},
				}, nil
			},
			CreateAliasFunc: func(_ context.Context, _ *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
				return &kms.CreateAliasOutput{}, nil
			},
			EncryptFunc: func(_ context.Context, params *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
				keyID := aws.ToString(params.KeyId)
				if keyID != awsGeneratedKeyID {
					return nil, fmt.Errorf("mock: Encrypt called with KeyId %q, want the CreateKey-assigned id %q", keyID, awsGeneratedKeyID)
				}
				ct := append([]byte("sealed:"), params.Plaintext...)
				return &kms.EncryptOutput{CiphertextBlob: ct, KeyId: params.KeyId}, nil
			},
			DecryptFunc: func(_ context.Context, params *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
				pt := params.CiphertextBlob[len("sealed:"):]
				return &kms.DecryptOutput{Plaintext: pt, KeyId: aws.String(awsGeneratedKeyID)}, nil
			},
		}
	}

	ctx := context.Background()

	// First "boot": build a Backend over the shared storage and provision
	// the seal key.
	backend1, err := awskms.NewBackendWithClient(&awskms.Config{
		Region:      "us-east-1",
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}, newMock())
	require.NoError(t, err)

	strategy1, err := BuildCloudKMSStrategy(ctx, StrategyAWSKMS, types.StoreAWSKMS, backend1)
	require.NoError(t, err)
	require.Equal(t, 1, createKeyCalls, "CreateKey must run once on first provisioning")

	rootKey := []byte("0123456789abcdef0123456789abcdef")
	sealed, err := strategy1.SealRootKey(ctx, rootKey, Credentials{})
	require.NoError(t, err)

	require.NoError(t, backend1.Close())

	// "Restart": a brand-new Backend and a brand-new MockKMSClient closure
	// share only keyStorage/certStorage -- no in-process state survives.
	backend2, err := awskms.NewBackendWithClient(&awskms.Config{
		Region:      "us-east-1",
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}, newMock())
	require.NoError(t, err)
	defer func() { _ = backend2.Close() }()

	strategy2, err := BuildCloudKMSStrategy(ctx, StrategyAWSKMS, types.StoreAWSKMS, backend2)
	require.NoError(t, err)
	assert.Equal(t, 1, createKeyCalls,
		"the restarted backend must resolve the persisted key through GetSymmetricKey, not call CreateKey again")

	// The root key sealed before the restart must unseal after it, through
	// the same persisted key -- proving GetSymmetricKey on backend2 resolved
	// the SAME AWS key ID CreateKey assigned on backend1, not a new one.
	unsealed, err := strategy2.UnsealRootKey(ctx, sealed, Credentials{})
	require.NoError(t, err)
	require.Equal(t, rootKey, unsealed)
}

// TestBuildCloudKMSStrategy_AWSKMSBackend_OperatorConfiguredKeyIsReused
// proves that an operator-configured CMK (Config.KeyID) is resolved and
// reused without ever calling CreateKey, and that Encrypt/Decrypt address
// the configured ID -- not the seal key's CN.
func TestBuildCloudKMSStrategy_AWSKMSBackend_OperatorConfiguredKeyIsReused(t *testing.T) {
	const operatorKeyID = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"

	keyStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	certStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	createKeyCalls := 0
	mock := &awskms.MockKMSClient{
		DescribeKeyFunc: func(_ context.Context, params *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			keyID := aws.ToString(params.KeyId)
			if keyID != operatorKeyID {
				return nil, fmt.Errorf("mock: key not found: %q", keyID)
			}
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String(keyID)},
			}, nil
		},
		CreateKeyFunc: func(_ context.Context, _ *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			createKeyCalls++
			return nil, errors.New("mock: CreateKey must not be called for an operator-configured CMK")
		},
		EncryptFunc: func(_ context.Context, params *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
			keyID := aws.ToString(params.KeyId)
			if keyID != operatorKeyID {
				return nil, fmt.Errorf("mock: Encrypt called with KeyId %q, want the operator-configured id %q", keyID, operatorKeyID)
			}
			ct := append([]byte("sealed:"), params.Plaintext...)
			return &kms.EncryptOutput{CiphertextBlob: ct, KeyId: params.KeyId}, nil
		},
		DecryptFunc: func(_ context.Context, params *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			pt := params.CiphertextBlob[len("sealed:"):]
			return &kms.DecryptOutput{Plaintext: pt, KeyId: aws.String(operatorKeyID)}, nil
		},
	}

	backend, err := awskms.NewBackendWithClient(&awskms.Config{
		Region:      "us-east-1",
		KeyID:       operatorKeyID,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}, mock)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	ctx := context.Background()
	strategy, err := BuildCloudKMSStrategy(ctx, StrategyAWSKMS, types.StoreAWSKMS, backend)
	require.NoError(t, err)
	require.NotNil(t, strategy)
	assert.Equal(t, 0, createKeyCalls, "an operator-configured CMK must never be created")

	rootKey := []byte("0123456789abcdef0123456789abcdef")
	sealed, err := strategy.SealRootKey(ctx, rootKey, Credentials{})
	require.NoError(t, err)

	unsealed, err := strategy.UnsealRootKey(ctx, sealed, Credentials{})
	require.NoError(t, err)
	require.Equal(t, rootKey, unsealed)
}

// TestBuildCloudKMSStrategy_AWSKMSBackend_OperatorConfiguredKeyNotFound
// proves that when the operator configures a CMK (Config.KeyID) that AWS KMS
// reports does not exist, BuildCloudKMSStrategy fails closed with a typed
// ErrOperatorSealKeyNotFound rather than silently provisioning a different,
// unrequested CMK in its place (go-xkms#842).
func TestBuildCloudKMSStrategy_AWSKMSBackend_OperatorConfiguredKeyNotFound(t *testing.T) {
	const operatorKeyID = "arn:aws:kms:us-east-1:123456789012:key/deadbeef-1234-5678-90ab-1234567890ab"

	keyStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	certStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	createKeyCalls := 0
	mock := &awskms.MockKMSClient{
		DescribeKeyFunc: func(_ context.Context, _ *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return nil, &kmstypes.NotFoundException{Message: aws.String("key does not exist")}
		},
		CreateKeyFunc: func(_ context.Context, _ *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			createKeyCalls++
			return nil, errors.New("mock: CreateKey must not be called for a missing operator-configured CMK")
		},
	}

	backend, err := awskms.NewBackendWithClient(&awskms.Config{
		Region:      "us-east-1",
		KeyID:       operatorKeyID,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}, mock)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	ctx := context.Background()
	_, err = BuildCloudKMSStrategy(ctx, StrategyAWSKMS, types.StoreAWSKMS, backend)
	require.Error(t, err)
	assert.Equal(t, 0, createKeyCalls, "a missing operator-configured CMK must never trigger CreateKey")

	var notFound *ErrOperatorSealKeyNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, string(StrategyAWSKMS), notFound.Strategy)
	assert.Equal(t, operatorKeyID, notFound.KeyID)
}

// TestBuildCloudKMSStrategy_AWSKMSBackend_MissingCredentials proves that a
// backend which cannot reach AWS KMS at all (CreateKey fails, simulating
// missing/invalid credentials) surfaces a real error from
// BuildCloudKMSStrategy itself: with no operator-configured CMK, seal-key
// provisioning must reach AWS (there is nothing to pre-seed from), so a
// credential failure is visible immediately rather than deferred to the
// first SealRootKey/UnsealRootKey call.
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
		CreateKeyFunc: func(_ context.Context, _ *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
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
	_, err = BuildCloudKMSStrategy(ctx, StrategyAWSKMS, types.StoreAWSKMS, backend)
	require.Error(t, err)
}

// failingGetStorage wraps a real storage.Backend and makes every Get fail
// with getErr, promoting every other method from the embedded Backend
// unchanged. It exists to simulate a metadata-storage outage independently
// of AWS KMS itself being reachable.
type failingGetStorage struct {
	storage.Backend
	getErr error
}

func (f *failingGetStorage) Get(ctx context.Context, key string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.Backend.Get(ctx, key)
}

var _ storage.Backend = (*failingGetStorage)(nil)

// TestEnsureSealKey_AWSKMSBackend_StorageOutageFailsClosed proves the
// go-xkms#1119 fix at the decision point go-xkms#1098 found broken: when the
// metadata store backing awskms.Backend is unavailable (not merely lacking a
// record), EnsureSealKey must surface that failure and must NEVER fall
// through to GenerateSymmetricKey/CreateKey, since doing so would mint a
// brand-new CMK on every storage hiccup and orphan the seal key already
// sealing data.
func TestEnsureSealKey_AWSKMSBackend_StorageOutageFailsClosed(t *testing.T) {
	realKeyStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	certStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	getErr := errors.New("storage: metadata backend unavailable")
	keyStorage := &failingGetStorage{Backend: realKeyStorage, getErr: getErr}

	createKeyCalls := 0
	mock := &awskms.MockKMSClient{
		DescribeKeyFunc: func(_ context.Context, params *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			keyID := aws.ToString(params.KeyId)
			if keyID != awsGeneratedKeyID {
				return nil, fmt.Errorf("mock: key not found: %q", keyID)
			}
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String(keyID)},
			}, nil
		},
		CreateKeyFunc: func(_ context.Context, _ *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			createKeyCalls++
			return &kms.CreateKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String(awsGeneratedKeyID)},
			}, nil
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
	_, err = BuildCloudKMSStrategy(ctx, StrategyAWSKMS, types.StoreAWSKMS, backend)
	require.Error(t, err)
	assert.True(t, errors.Is(err, getErr), "EnsureSealKey's error must chain back to the storage failure, got %v", err)
	assert.False(t, errors.Is(err, awskms.ErrKeyNotFound), "a storage outage must not be classified as backend.ErrKeyNotFound, got %v", err)
	assert.Equal(t, 0, createKeyCalls, "a storage outage must never fall through to CreateKey/GenerateSymmetricKey")
}
