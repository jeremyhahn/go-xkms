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
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestListKeys_SymmetricKeyTypeRoundTrips proves go-xkms#705: a symmetric key
// created via GenerateSymmetricKey persists its KeyType so that a later
// ListKeys call reconstructs the same KeyType instead of silently dropping
// it. GenerateSymmetricKey stores "key_type" as a string (unlike the
// asymmetric CreateKey path, which historically stored it as a raw JSON
// number), and ListKeys' switch over metadata["key_type"] had a string case
// that discarded the value with a comment saying as much ("we'll need to
// parse it ... just skip since we can't easily convert string back to
// uint8"). Before the fix, the reconstructed attrs.KeyType is always the
// zero value regardless of what was stored.
func TestListKeys_SymmetricKeyTypeRoundTrips(t *testing.T) {
	mem, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("failed to create memory backend: %v", err)
	}

	client := &MockKMSClient{
		CreateKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			return &kms.CreateKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{
					KeyId: aws.String("test-key-id-round-trip"),
				},
			}, nil
		},
		CreateAliasFunc: func(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
			return &kms.CreateAliasOutput{}, nil
		},
	}

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  mem,
		CertStorage: storage.New(),
	}, client)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "round-trip-secret",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey() error = %v", err)
	}

	keys, err := b.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	var found *types.KeyAttributes
	for _, k := range keys {
		if k.CN == attrs.CN {
			found = k
			break
		}
	}
	if found == nil {
		t.Fatalf("ListKeys() did not return CN %q among %d keys", attrs.CN, len(keys))
	}

	if found.KeyType != backend.KEY_TYPE_SECRET {
		t.Errorf("ListKeys() KeyType = %v (%d), want %v (%d): key_type was silently dropped on round trip",
			found.KeyType, found.KeyType, backend.KEY_TYPE_SECRET, backend.KEY_TYPE_SECRET)
	}
}

// TestListKeys_AsymmetricKeyTypeRoundTrips is the CreateKey-path companion to
// TestListKeys_SymmetricKeyTypeRoundTrips: it proves the fix does not
// regress the asymmetric key path, whose CreateKey stores key_type using the
// same encoding as the symmetric path after the fix.
func TestListKeys_AsymmetricKeyTypeRoundTrips(t *testing.T) {
	mem, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("failed to create memory backend: %v", err)
	}

	client := &MockKMSClient{
		CreateKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			return &kms.CreateKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{
					KeyId: aws.String("test-key-id-asymmetric"),
				},
			}, nil
		},
		CreateAliasFunc: func(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
			return &kms.CreateAliasOutput{}, nil
		},
	}

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  mem,
		CertStorage: storage.New(),
	}, client)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "round-trip-signing",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	keys, err := b.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	var found *types.KeyAttributes
	for _, k := range keys {
		if k.CN == attrs.CN {
			found = k
			break
		}
	}
	if found == nil {
		t.Fatalf("ListKeys() did not return CN %q among %d keys", attrs.CN, len(keys))
	}

	if found.KeyType != backend.KEY_TYPE_SIGNING {
		t.Errorf("ListKeys() KeyType = %v (%d), want %v (%d)",
			found.KeyType, found.KeyType, backend.KEY_TYPE_SIGNING, backend.KEY_TYPE_SIGNING)
	}
}
