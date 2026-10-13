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

package tpmblobtest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestNew_RoundTrips proves the store New returns saves and reads blobs.
func TestNew_RoundTrips(t *testing.T) {
	blobs := New(t)
	attrs := &types.KeyAttributes{CN: "signer"}

	require.NoError(t, blobs.Save(attrs, []byte("blob"), store.FSEXT_PUBLIC_BLOB, false))
	got, err := blobs.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	assert.Equal(t, []byte("blob"), got)
}

// TestNew_StoresAreIsolated proves two stores share nothing, so one test's
// blobs never leak into another's.
func TestNew_StoresAreIsolated(t *testing.T) {
	attrs := &types.KeyAttributes{CN: "signer"}
	require.NoError(t, New(t).Save(attrs, []byte("blob"), store.FSEXT_PUBLIC_BLOB, false))

	_, err := New(t).Get(attrs, store.FSEXT_PUBLIC_BLOB)
	assert.ErrorIs(t, err, store.ErrBlobNotFound)
}
