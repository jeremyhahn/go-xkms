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

package quantum

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var errStorageFault = errors.New("storage fault")

// faultStorage is a storage.Backend double that fails the operations whose
// error field is set and passes every other call to the memory backend.
type faultStorage struct {
	storage.Backend
	getErr, putErr, deleteErr, existsErr error
}

func (f *faultStorage) Get(ctx context.Context, key string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.Backend.Get(ctx, key)
}

func (f *faultStorage) Put(ctx context.Context, key string, value []byte) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.Backend.Put(ctx, key, value)
}

func (f *faultStorage) Delete(ctx context.Context, key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.Backend.Delete(ctx, key)
}

func (f *faultStorage) Exists(ctx context.Context, key string) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}
	return f.Backend.Exists(ctx, key)
}

// newFaultBackend returns a backend over a faultStorage that already holds
// one ML-DSA-65 key, and that key's attributes.
func newFaultBackend(t *testing.T) (*QuantumBackend, *faultStorage, *types.KeyAttributes) {
	t.Helper()
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	fault := &faultStorage{Backend: store}
	qb, err := New(fault)
	require.NoError(t, err)
	attrs := mldsaAttrs("storage-fault.example.com", types.QuantumAlgorithmMLDSA65)
	_, err = qb.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)
	return qb, fault, attrs
}

// TestDeleteKey_Refusals proves DeleteKey refuses invalid attributes and
// surfaces a storage failure that is not "not found" with its cause.
func TestDeleteKey_Refusals(t *testing.T) {
	t.Run("invalid attributes", func(t *testing.T) {
		qb, _, attrs := newFaultBackend(t)
		bad := *attrs
		bad.CN = ""
		require.ErrorIs(t, qb.DeleteKey(context.Background(), &bad), backend.ErrInvalidAttributes)

		_, err := qb.GetKey(context.Background(), attrs)
		assert.NoError(t, err, "the stored key must survive a refused delete")
	})

	t.Run("storage failure", func(t *testing.T) {
		qb, fault, attrs := newFaultBackend(t)
		fault.deleteErr = errStorageFault
		err := qb.DeleteKey(context.Background(), attrs)
		require.ErrorIs(t, err, errStorageFault)
		assert.NotErrorIs(t, err, backend.ErrKeyNotFound)
	})
}

// TestRotateKey_Refusals proves each RotateKey failure is reported with its
// cause and leaves the stored key unchanged.
func TestRotateKey_Refusals(t *testing.T) {
	tests := []struct {
		name   string
		inject func(f *faultStorage, attrs *types.KeyAttributes)
		wantIs error
	}{
		{
			name:   "invalid attributes",
			inject: func(_ *faultStorage, attrs *types.KeyAttributes) { attrs.CN = "" },
			wantIs: backend.ErrInvalidAttributes,
		},
		{
			name:   "existence check fails",
			inject: func(f *faultStorage, _ *types.KeyAttributes) { f.existsErr = errStorageFault },
			wantIs: errStorageFault,
		},
		{
			name:   "read fails",
			inject: func(f *faultStorage, _ *types.KeyAttributes) { f.getErr = errStorageFault },
			wantIs: errStorageFault,
		},
		{
			name:   "write fails",
			inject: func(f *faultStorage, _ *types.KeyAttributes) { f.putErr = errStorageFault },
			wantIs: errStorageFault,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb, fault, attrs := newFaultBackend(t)
			before, err := fault.Backend.Get(context.Background(), storage.KeyPath(attrs.ID()))
			require.NoError(t, err)

			rotateAttrs := *attrs
			tt.inject(fault, &rotateAttrs)
			require.ErrorIs(t, qb.RotateKey(context.Background(), &rotateAttrs), tt.wantIs)

			after, err := fault.Backend.Get(context.Background(), storage.KeyPath(attrs.ID()))
			require.NoError(t, err)
			assert.Equal(t, before, after, "a refused rotation must not replace the stored key")
		})
	}
}
