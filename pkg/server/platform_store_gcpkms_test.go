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

//go:build gcpkms

package server

import (
	"context"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestInitializePlatformStore_GCPKMSNotConfiguredFailsClosed proves the
// gcpkms credential strategy fails closed with a typed error when
// backends.gcpkms is not configured.
func TestInitializePlatformStore_GCPKMSNotConfiguredFailsClosed(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig("gcpkms"))
	// Backends.GCPKMS left nil.

	err := s.initializePlatformStore()
	require.Error(t, err)
	assert.Nil(t, s.platformStore)

	var unavailableErr *ErrPlatformStoreStrategyUnavailable
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "gcpkms", unavailableErr.Strategy)
}

// TestBuildGCPKMSPlatformSealer_RoundTripViaMockClient proves the reusable
// machinery buildGCPKMSPlatformSealer composes -- sealKeyAttributesFor,
// ensureSealKey and fixedKeyAttrsSealer -- seals and unseals correctly
// against a GCP KMS backend, using the same mock KMS client
// (gcpkms.MockKMSClient) that package's own round-trip test uses
// (pkg/backend/gcpkms/gcpkms_symmetric_test.go's
// TestSymmetricEncrypter_RoundTrip). See the awskms equivalent for why this
// targets the composition rather than buildGCPKMSPlatformSealer itself
// (which always dials Application Default Credentials via gcpkms.NewBackend
// and has no seam for a test client).
func TestBuildGCPKMSPlatformSealer_RoundTripViaMockClient(t *testing.T) {
	mockClient := &gcpkms.MockKMSClient{
		GetCryptoKeyFunc: func(_ context.Context, req *kmspb.GetCryptoKeyRequest, _ ...interface{}) (*kmspb.CryptoKey, error) {
			return &kmspb.CryptoKey{
				Name:    req.Name,
				Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
				Primary: &kmspb.CryptoKeyVersion{
					Name:      req.Name + "/cryptoKeyVersions/1",
					State:     kmspb.CryptoKeyVersion_ENABLED,
					Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
				},
			}, nil
		},
	}

	backend, err := gcpkms.NewBackendWithClient(&gcpkms.Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, mockClient)
	require.NoError(t, err)

	s := newMinimalServer(t, &config.Config{})
	keyAttrs := sealKeyAttributesFor(types.StoreGCPKMS)
	require.NoError(t, s.ensureSealKey(seal.StrategyGCPKMS, backend, keyAttrs))

	sealer := &fixedKeyAttrsSealer{inner: backend, attrs: keyAttrs}
	assert.True(t, sealer.CanSeal())

	ctx := context.Background()
	plaintext := []byte("platform-store secret sealed via GCP KMS")

	sealed, err := sealer.Seal(ctx, plaintext, nil)
	require.NoError(t, err)
	require.NotNil(t, sealed)

	got, err := sealer.Unseal(ctx, sealed, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}
