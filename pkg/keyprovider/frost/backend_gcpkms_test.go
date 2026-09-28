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

//go:build frost && gcpkms

package frost

import (
	"bytes"
	"context"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newGCPKMSFrostSecretBackend builds a *gcpkms.Backend over the package's
// own MockKMSClient and provisions the FROST wrapping key through it via
// seal.EnsureSealKey -- the same production composition pkg/server's
// ensureFrostSecretSealKey uses for the "gcpkms" secret_backend.
//
// GetCryptoKeyFunc/CreateCryptoKeyFunc are wired explicitly (rather than
// relying on MockKMSClient's zero-value defaults) because its default
// GetCryptoKey fallback for an untracked name returns a fake
// ASYMMETRIC_SIGN key with a nil error instead of a gRPC NotFound status:
// fine for tests that seed the key first, but it defeats
// seal.EnsureSealKey's own not-found check-and-skip, which must see a real
// NotFound on the very first call, before any key exists.
func newGCPKMSFrostSecretBackend(t *testing.T) (*gcpkms.Backend, *types.KeyAttributes) {
	t.Helper()

	var created *kmspb.CryptoKey
	mockClient := &gcpkms.MockKMSClient{
		CreateCryptoKeyFunc: func(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
			created = &kmspb.CryptoKey{
				Name:    req.Parent + "/cryptoKeys/" + req.CryptoKeyId,
				Purpose: req.CryptoKey.Purpose,
				Primary: &kmspb.CryptoKeyVersion{
					Name:      req.Parent + "/cryptoKeys/" + req.CryptoKeyId + "/cryptoKeyVersions/1",
					State:     kmspb.CryptoKeyVersion_ENABLED,
					Algorithm: req.CryptoKey.VersionTemplate.Algorithm,
				},
			}
			return created, nil
		},
		GetCryptoKeyFunc: func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
			if created == nil || created.Name != req.Name {
				return nil, status.Error(codes.NotFound, "crypto key not found")
			}
			return created, nil
		},
	}

	config := &gcpkms.Config{
		ProjectID:   "frost-test-project",
		LocationID:  "us-central1",
		KeyRingID:   "frost-test-ring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := gcpkms.NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := SymmetricSecretSealKeyAttributes(types.StoreGCPKMS)
	require.NoError(t, seal.EnsureSealKey(context.Background(), seal.StrategyGCPKMS, b, attrs))

	return b, attrs
}

func TestKeyStore_GCPKMS_StoreAndLoadKeyPackage(t *testing.T) {
	secretBackend, attrs := newGCPKMSFrostSecretBackend(t)
	ks := NewKeyStore(newMockStorageBackend(), secretBackend, attrs)

	keyID := "gcp-frost-key"
	pkg := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte("gcp-kms-secret-share")},
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
