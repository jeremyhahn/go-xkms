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

// Package ca coverage boost, nineteenth pass: revocation-persistence storage
// faults (the revocationStore backend of putRevocationBlob) and the
// mustMarshal panic-on-unsupported-type guard.
package ca

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errRevocationStoreFault is a non-sentinel storage fault used to exercise
// putRevocationBlob's error-wrapping branches.
var errRevocationStoreFault = errors.New("b19: revocation store unavailable")

// faultyPutBackend wraps a real storage.Backend and forces every Put call to
// fail, letting tests drive putRevocationBlob's revocationStore error branch
// without a live storage fault.
type faultyPutBackend struct {
	storage.Backend
}

func (f *faultyPutBackend) Put(ctx context.Context, key string, value []byte) error {
	return errRevocationStoreFault
}

// TestPutRevocationBlob_RevocationStoreError_B19 exercises the
// revocationStore.Put error branch (recordRevocation must surface the fault
// wrapped in ErrStorageError, not silently swallow it).
func TestPutRevocationBlob_RevocationStoreError_B19(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.revocationStore = &faultyPutBackend{Backend: storage.NewMemory()}

	err := ca.Revoke(context.Background(), big.NewInt(4242), 0)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStorageError)
	assert.Contains(t, err.Error(), errRevocationStoreFault.Error())
}

// TestMustMarshal_PanicsOnUnsupportedType_B19 exercises mustMarshal's
// panic-on-marshal-error guard. mustMarshal is only ever called internally
// with known-good ASN.1 values; this test proves the defensive panic fires
// for a type ASN.1 cannot encode (a Go channel), rather than silently
// returning corrupt bytes.
func TestMustMarshal_PanicsOnUnsupportedType_B19(t *testing.T) {
	t.Parallel()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected mustMarshal to panic on an unsupported type")
		}
	}()
	mustMarshal(make(chan int))
}
