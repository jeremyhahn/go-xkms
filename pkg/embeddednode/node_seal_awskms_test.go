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

package embeddednode

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// awsNodeSealKeyID is the key ID the mock AWS account assigns the seal key.
const awsNodeSealKeyID = "node-seal-cmk"

// awsNodeSealAccount is a mock AWS account holding at most one CMK: it
// creates the key once and encrypts under it, so a second boot only unseals
// if the node seal found the key the first boot created.
func awsNodeSealAccount(createKeyCalls *int) *awskms.MockKMSClient {
	return &awskms.MockKMSClient{
		DescribeKeyFunc: func(_ context.Context, params *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			if aws.ToString(params.KeyId) != awsNodeSealKeyID || *createKeyCalls == 0 {
				return nil, &kmstypes.NotFoundException{Message: aws.String("key does not exist")}
			}
			return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: params.KeyId}}, nil
		},
		CreateKeyFunc: func(_ context.Context, _ *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			*createKeyCalls++
			return &kms.CreateKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String(awsNodeSealKeyID)}}, nil
		},
		CreateAliasFunc: func(_ context.Context, _ *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
			return &kms.CreateAliasOutput{}, nil
		},
		EncryptFunc: func(_ context.Context, params *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
			ct := append([]byte(aws.ToString(params.KeyId)+":"), params.Plaintext...)
			return &kms.EncryptOutput{CiphertextBlob: ct, KeyId: params.KeyId}, nil
		},
		DecryptFunc: func(_ context.Context, params *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			prefix := []byte(awsNodeSealKeyID + ":")
			if len(params.CiphertextBlob) < len(prefix) || string(params.CiphertextBlob[:len(prefix)]) != string(prefix) {
				return nil, &kmstypes.InvalidCiphertextException{Message: aws.String("not sealed under this key")}
			}
			return &kms.DecryptOutput{Plaintext: params.CiphertextBlob[len(prefix):], KeyId: aws.String(awsNodeSealKeyID)}, nil
		},
	}
}

// awsNodeSealThrough builds the awskms node seal as resolveCloudNodeSeal
// does, over the real AWS KMS backend talking to client.
func awsNodeSealThrough(t *testing.T, cfg *config.Config, client awskms.KMSClient) (ResolvedNodeSeal, error) {
	t.Helper()
	metadata, err := storage.NewFile(filepath.Join(cfg.Datastore.Path, CloudNodeSealSubdir, string(seal.StrategyAWSKMS)))
	require.NoError(t, err)
	backendCfg, err := awsKMSNodeSealConfig(cfg, metadata, testLogger())
	require.NoError(t, err)
	provider, err := awskms.NewBackendWithClient(backendCfg, client)
	require.NoError(t, err)
	return cloudNodeSealFromProvider(context.Background(), seal.StrategyAWSKMS, types.StoreAWSKMS, provider, metadata)
}

func awsKMSNodeSealTestConfig(t *testing.T) *config.Config {
	cfg := cloudNodeSealConfig(t, seal.StrategyAWSKMS)
	cfg.Backends.AWSKMS = &config.AWSKMSConfig{Region: "us-east-1"}
	return cfg
}

// TestOpenEmbeddedNode_AWSKMSBackendSealsTheNode proves the real AWS KMS
// backend seals the node's barrier on first boot and, through the key
// metadata the node seal keeps under the datastore path, finds the same CMK
// and unseals it unattended on the next boot.
func TestOpenEmbeddedNode_AWSKMSBackendSealsTheNode(t *testing.T) {
	cfg := awsKMSNodeSealTestConfig(t)
	createKeyCalls := 0
	for boot := 1; boot <= 2; boot++ {
		res, err := awsNodeSealThrough(t, cfg, awsNodeSealAccount(&createKeyCalls))
		require.NoError(t, err, "boot %d", boot)
		node, err := openEmbeddedNodeWithSeal(context.Background(),
			EmbeddedNodeOptions{Config: cfg, Logger: testLogger()}, res)
		require.NoError(t, err, "boot %d", boot)
		require.False(t, node.IsSealed(), "boot %d", boot)
		require.NoError(t, node.Close())
		require.NoError(t, res.Close())
	}
	require.Equal(t, 1, createKeyCalls, "the second boot must reuse the CMK the first created")
}

func TestCloudNodeSealFromProvider_ProvisioningFailureFailsClosed(t *testing.T) {
	cfg := awsKMSNodeSealTestConfig(t)
	unreachable := errors.New("no valid providers in chain")
	client := &awskms.MockKMSClient{
		CreateKeyFunc: func(_ context.Context, _ *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			return nil, unreachable
		},
	}

	res, err := awsNodeSealThrough(t, cfg, client)
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	require.ErrorIs(t, err, unreachable)
	require.False(t, res.Enabled)
}

func TestAWSKMSNodeSealConfig_MapsBackendsAWSKMS(t *testing.T) {
	metadata := storage.NewMemory()
	cfg := &config.Config{Backends: config.BackendsConfig{AWSKMS: &config.AWSKMSConfig{
		Region:    "eu-west-1",
		Endpoint:  "https://kms.example.com",
		KeyID:     "alias/node-seal",
		AccessKey: "ignored-by-the-node-seal",
	}}}

	got, err := awsKMSNodeSealConfig(cfg, metadata, testLogger())
	require.NoError(t, err)
	require.Equal(t, &awskms.Config{
		Region:      "eu-west-1",
		Endpoint:    "https://kms.example.com",
		KeyID:       "alias/node-seal",
		KeyStorage:  metadata,
		CertStorage: metadata,
	}, got)
}

func TestBuildAWSKMSNodeSealBackend_RequiresBackendsAWSKMS(t *testing.T) {
	provider, err := buildAWSKMSNodeSealBackend(context.Background(), &config.Config{}, storage.NewMemory(), testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	require.Nil(t, provider)
}
