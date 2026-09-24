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
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// emptyCreateKeyClient answers CreateKey with a success response that carries
// no KeyMetadata, the shape a misbehaving endpoint or proxy could return.
func emptyCreateKeyClient() *MockKMSClient {
	return &MockKMSClient{
		CreateKeyFunc: func(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			return &kms.CreateKeyOutput{}, nil
		},
	}
}

// TestGenerateSymmetricKey_MalformedCreateKeyResponse proves a CreateKey
// success without KeyMetadata is a typed error, not a nil-pointer panic.
func TestGenerateSymmetricKey_MalformedCreateKeyResponse(t *testing.T) {
	b, err := NewBackendWithClient(&Config{Region: "us-east-1", KeyStorage: storage.New(), CertStorage: storage.New()}, emptyCreateKeyClient())
	require.NoError(t, err)

	_, err = b.GenerateSymmetricKey(context.Background(), &types.KeyAttributes{
		CN:                 "malformed-symmetric",
		KeyType:            backend.KEY_TYPE_ENCRYPTION,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrMalformedResponse), "got %v", err)
}

// TestCreateKey_MalformedCreateKeyResponse proves the asymmetric path
// refuses the same malformed response.
func TestCreateKey_MalformedCreateKeyResponse(t *testing.T) {
	b, err := NewBackendWithClient(&Config{Region: "us-east-1", KeyStorage: storage.New(), CertStorage: storage.New()}, emptyCreateKeyClient())
	require.NoError(t, err)

	_, err = b.CreateKey(&types.KeyAttributes{
		CN:           "malformed-asymmetric",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrMalformedResponse), "got %v", err)
}
