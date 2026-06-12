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

package hardware

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHardwareBackendAdapter_PutIfAbsent verifies the certificate adapter's
// atomic check-then-write: a fresh cert key is written (stored=true) and a
// second write to the same id is rejected (stored=false), leaving the original
// certificate intact.
func TestHardwareBackendAdapter_PutIfAbsent(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	adapter := NewHardwareBackendAdapter(hw)

	cert := generateTestCertForAdapter(t, "first")
	const key = "certs/example.pem"

	stored, err := adapter.PutIfAbsent(ctx, key, cert.Raw)
	require.NoError(t, err)
	assert.True(t, stored, "fresh PutIfAbsent should store")

	got, err := adapter.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, got)

	// A second cert for the same id must be rejected, leaving the original.
	other := generateTestCertForAdapter(t, "second")
	stored, err = adapter.PutIfAbsent(ctx, key, other.Raw)
	require.NoError(t, err)
	assert.False(t, stored, "existing PutIfAbsent should not store")

	got, err = adapter.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, got, "original certificate must remain intact")
}

// TestHardwareBackendAdapter_PutIfAbsent_InvalidKey verifies non-certificate
// keys are rejected before any write.
func TestHardwareBackendAdapter_PutIfAbsent_InvalidKey(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	adapter := NewHardwareBackendAdapter(hw)

	stored, err := adapter.PutIfAbsent(ctx, "keys/not-a-cert", []byte("x"))
	require.Error(t, err)
	assert.False(t, stored)
}
