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

package xkms

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestSignCoRIM_RefusesAReleaseKeyGCPKMSCannotScope proves first use on
// Cloud KMS, whose keys carry no tenant, refuses before any key is created.
func TestSignCoRIM_RefusesAReleaseKeyGCPKMSCannotScope(t *testing.T) {
	var created atomic.Int32
	client := &gcpkms.MockKMSClient{
		CreateCryptoKeyFunc: func(context.Context, *kmspb.CreateCryptoKeyRequest, ...interface{}) (*kmspb.CryptoKey, error) {
			created.Add(1)
			return nil, errors.New("mock: CreateCryptoKey reached")
		},
	}
	provider, err := gcpkms.NewBackendWithClient(&gcpkms.Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, client)
	require.NoError(t, err)
	Reset()
	t.Cleanup(Reset)
	b, err := New(&BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, Initialize(&ServiceConfig{Backends: map[string]Backend{"gcpkms": b}, DefaultBackend: "gcpkms"}))
	svc, err := Get()
	require.NoError(t, err)
	wireKeyVersionStore(t)
	ctx := withSigningKeys(t, svc, corimSignPermission)

	for range 2 {
		_, err := svc.SignCoRIM(ctx, signCoRIMRequest(t))
		var provision *ReleaseKeyProvisionError
		require.ErrorAs(t, err, &provision)
		assert.ErrorIs(t, err, ErrReleaseKeyBackendUnsupported)
		assert.Equal(t, int32(0), created.Load(), "no Cloud KMS key is created")
	}
}
