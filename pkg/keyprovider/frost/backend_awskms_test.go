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

//go:build frost && awskms

package frost

import (
	"bytes"
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newAWSKMSFrostSecretBackend builds a *awskms.Backend over a mock KMS
// client that implements just enough of the API (CreateKey, Encrypt,
// Decrypt) for seal.EnsureSealKey to provision
// SymmetricSecretSealKeyAttributes and for the resulting KeyStore to
// seal/unseal FROST secret shares through it -- the same production
// composition pkg/server's ensureFrostSecretSealKey uses for the "awskms"
// secret_backend.
func newAWSKMSFrostSecretBackend(t *testing.T) (*awskms.Backend, *types.KeyAttributes) {
	t.Helper()

	// ciphertexts simulates AWS KMS's server-side encryption: Encrypt maps
	// plaintext to a random-looking ciphertext keyed by its own output, and
	// Decrypt looks it back up, so Unseal only succeeds for ciphertext this
	// mock actually produced -- not merely because it "trusts" it.
	ciphertexts := make(map[string][]byte)
	var counter int

	mockClient := &awskms.MockKMSClient{
		CreateKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			return &kms.CreateKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String("frost-wrap-key-id")},
			}, nil
		},
		EncryptFunc: func(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
			counter++
			ct := []byte{byte(counter)}
			ciphertexts[string(ct)] = params.Plaintext
			return &kms.EncryptOutput{CiphertextBlob: ct, KeyId: aws.String("frost-wrap-key-id")}, nil
		},
		DecryptFunc: func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			pt, ok := ciphertexts[string(params.CiphertextBlob)]
			if !ok {
				return nil, awskmsErrUnknownCiphertext
			}
			return &kms.DecryptOutput{Plaintext: pt, KeyId: aws.String("frost-wrap-key-id")}, nil
		},
	}

	config := &awskms.Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := awskms.NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := SymmetricSecretSealKeyAttributes(types.StoreAWSKMS)
	require.NoError(t, seal.EnsureSealKey(context.Background(), seal.StrategyAWSKMS, b, attrs))

	return b, attrs
}

func TestKeyStore_AWSKMS_StoreAndLoadKeyPackage(t *testing.T) {
	secretBackend, attrs := newAWSKMSFrostSecretBackend(t)
	ks := NewKeyStore(newMockStorageBackend(), secretBackend, attrs)

	keyID := "aws-frost-key"
	pkg := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte("aws-kms-secret-share")},
		GroupPublicKey:     []byte{1, 2, 3},
		VerificationShares: map[uint32][]byte{1: {4}, 2: {5}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{KeyID: keyID, Algorithm: types.FrostAlgorithmEd25519, Threshold: 2, Total: 2}

	require.NoError(t, ks.StoreKeyPackage(context.Background(), keyID, pkg, metadata))

	loaded, _, err := ks.LoadKeyPackage(context.Background(), keyID, 1)
	require.NoError(t, err)
	require.True(t, bytes.Equal(pkg.SecretShare.Value, loaded.SecretShare.Value))
}

// awskmsErrUnknownCiphertext is returned by the mock Decrypt when handed
// ciphertext it never produced.
var awskmsErrUnknownCiphertext = &mockDecryptError{}

type mockDecryptError struct{}

func (*mockDecryptError) Error() string { return "aws kms mock: unknown ciphertext" }
