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

package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// errBackendDown is the failure faultyBackend injects.
var errBackendDown = errors.New("backend down")

// faultyBackend fails every operation, proving BackendPolicyStore surfaces a
// storage fault as a typed *StoreError instead of a not-found or a panic.
type faultyBackend struct {
	storage.Backend
}

func (faultyBackend) Get(context.Context, string) ([]byte, error) { return nil, errBackendDown }
func (faultyBackend) Put(context.Context, string, []byte) error   { return errBackendDown }
func (faultyBackend) Exists(context.Context, string) (bool, error) {
	return false, errBackendDown
}
func (faultyBackend) Scan(context.Context, string, func(string, []byte) error) error {
	return errBackendDown
}

func newBackendStore(t *testing.T) (*BackendPolicyStore, storage.Backend) {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	store, err := NewBackendPolicyStore(backend)
	require.NoError(t, err)
	return store, backend
}

func TestNewBackendPolicyStore_RejectsNilBackend(t *testing.T) {
	store, err := NewBackendPolicyStore(nil)
	assert.Nil(t, store)
	assert.ErrorIs(t, err, ErrNilStorageBackend)
}

// TestBackendPolicyStore_RoundTripSurvivesReopen proves the store is durable:
// a second store over the same backend (a restart) reads what the first wrote.
func TestBackendPolicyStore_RoundTripSurvivesReopen(t *testing.T) {
	store, backend := newBackendStore(t)
	def := &PolicyDefinition{
		Name:       "boot",
		Bank:       "sha256",
		PCRIndices: []int{0, 7},
		PCRValues:  map[int][]byte{0: {0x01}, 7: {0x07}},
		CreatedAt:  time.Unix(1700000000, 0).UTC(),
	}
	require.NoError(t, store.SavePolicy("boot", def))

	reopened, err := NewBackendPolicyStore(backend)
	require.NoError(t, err)
	got, err := reopened.LoadPolicy("boot")
	require.NoError(t, err)
	assert.Equal(t, def, got)

	all, err := reopened.ListPolicies()
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, "boot", all[0].Name)

	require.NoError(t, reopened.DeletePolicy("boot"))
	_, err = reopened.LoadPolicy("boot")
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestBackendPolicyStore_EmptyListIsNotNil(t *testing.T) {
	store, _ := newBackendStore(t)
	all, err := store.ListPolicies()
	require.NoError(t, err)
	assert.NotNil(t, all)
	assert.Empty(t, all)
}

func TestBackendPolicyStore_InvalidInput(t *testing.T) {
	store, _ := newBackendStore(t)
	assert.ErrorIs(t, store.SavePolicy(" ", &PolicyDefinition{}), ErrInvalidName)
	assert.ErrorIs(t, store.SavePolicy("p", nil), ErrNilPolicyDefinition)
	assert.ErrorIs(t, store.DeletePolicy("missing"), ErrPolicyNotFound)
	_, err := store.LoadPolicy("missing")
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestBackendPolicyStore_CorruptRecordIsTypedError(t *testing.T) {
	store, backend := newBackendStore(t)
	require.NoError(t, backend.Put(context.Background(), "bad", []byte("{not json")))

	_, err := store.LoadPolicy("bad")
	var storeErr *StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "load", storeErr.Op)
	assert.Equal(t, "bad", storeErr.Name)

	_, err = store.ListPolicies()
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "list", storeErr.Op)
}

func TestBackendPolicyStore_BackendFaultsAreTypedErrors(t *testing.T) {
	store, err := NewBackendPolicyStore(faultyBackend{})
	require.NoError(t, err)

	tests := []struct {
		op  string
		run func() error
	}{
		{"save", func() error { return store.SavePolicy("p", &PolicyDefinition{Name: "p"}) }},
		{"load", func() error { _, err := store.LoadPolicy("p"); return err }},
		{"delete", func() error { return store.DeletePolicy("p") }},
		{"list", func() error { _, err := store.ListPolicies(); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			err := tt.run()
			var storeErr *StoreError
			require.ErrorAs(t, err, &storeErr)
			assert.Equal(t, tt.op, storeErr.Op)
			assert.ErrorIs(t, err, errBackendDown)
			assert.Contains(t, err.Error(), "policy: store "+tt.op)
		})
	}
}

// TestBackendPolicyStore_BacksManager proves the durable store satisfies the
// Manager end to end, not just the interface.
func TestBackendPolicyStore_BacksManager(t *testing.T) {
	store, _ := newBackendStore(t)
	mgr, err := NewManager(staticReader{0: {0xAA}}, store)
	require.NoError(t, err)

	_, err = mgr.CreatePolicy("boot", "sha256", []int{0})
	require.NoError(t, err)
	ok, _, err := mgr.VerifyPolicy("boot")
	require.NoError(t, err)
	assert.True(t, ok)
}

// staticReader is a PCRReader returning fixed digests.
type staticReader map[int][]byte

func (r staticReader) ReadPCRs(_ string, indices []int) (map[int][]byte, error) {
	out := make(map[int][]byte, len(indices))
	for _, i := range indices {
		out[i] = r[i]
	}
	return out, nil
}
