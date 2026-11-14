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

//go:build frost

package frost

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestFrostBackend_PublicKeyPackage proves an imported key's public package
// reads back with the dealer's group key, verification shares and bounds.
func TestFrostBackend_PublicKeyPackage(t *testing.T) {
	ctx := context.Background()
	backend := createTestBackend(t)
	packages, pub, err := NewTrustedDealer().Generate(FrostConfig{
		Threshold: 2, Total: 3, Algorithm: types.FrostAlgorithmEd25519, ParticipantID: 1,
	})
	require.NoError(t, err)
	attrs := tenantKeyAttrs("tenant-a", "k1")
	require.NoError(t, backend.ImportKeyPackage(ctx, attrs, packages[0]))

	got, metadata, err := backend.PublicKeyPackage(ctx, attrs)
	require.NoError(t, err)
	assert.Equal(t, pub.GroupPublicKey, got.GroupPublicKey)
	assert.Equal(t, pub.VerificationShares, got.VerificationShares)
	assert.Equal(t, uint32(2), got.MinSigners)
	assert.Equal(t, uint32(3), got.MaxSigners)
	assert.Equal(t, 2, metadata.Threshold)
	assert.Equal(t, 3, metadata.Total)
}

// TestFrostBackend_PublicKeyPackage_Refusals proves each unusable request is
// refused with its sentinel and no package or metadata.
func TestFrostBackend_PublicKeyPackage_Refusals(t *testing.T) {
	tests := []struct {
		name   string
		attrs  *types.KeyAttributes
		close  bool
		wantIs error
	}{
		{name: "nil attributes", attrs: nil, wantIs: ErrInvalidAttributes},
		{name: "unsafe common name", attrs: tenantKeyAttrs("tenant-a", "../x"), wantIs: ErrInvalidAttributes},
		{name: "absent key", attrs: tenantKeyAttrs("tenant-a", "absent"), wantIs: ErrKeyNotFound},
		{name: "closed backend", attrs: tenantKeyAttrs("tenant-a", "k1"), close: true, wantIs: ErrBackendClosed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := createTestBackend(t)
			if tt.close {
				require.NoError(t, backend.Close())
			}
			got, metadata, err := backend.PublicKeyPackage(context.Background(), tt.attrs)
			require.ErrorIs(t, err, tt.wantIs)
			assert.Nil(t, got)
			assert.Nil(t, metadata)
		})
	}
}
