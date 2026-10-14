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

package truststore

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errInjected is the storage failure faultBackend reports.
var errInjected = errors.New("injected storage failure")

// faultBackend wraps a real in-memory storage backend and fails the
// operations whose key (or List prefix) starts with a configured prefix.
type faultBackend struct {
	xkms.StorageBackend
	listFail   map[string]error
	getFail    map[string]error
	putFail    map[string]error
	deleteFail map[string]error
}

func newFaultBackend() *faultBackend {
	return &faultBackend{
		StorageBackend: xkms.NewStorageMemory(),
		listFail:       map[string]error{},
		getFail:        map[string]error{},
		putFail:        map[string]error{},
		deleteFail:     map[string]error{},
	}
}

func matchFault(faults map[string]error, key string) error {
	for prefix, err := range faults {
		if strings.HasPrefix(key, prefix) {
			return err
		}
	}
	return nil
}

func (f *faultBackend) List(ctx context.Context, prefix string) ([]string, error) {
	if err := matchFault(f.listFail, prefix); err != nil {
		return nil, err
	}
	return f.StorageBackend.List(ctx, prefix)
}

func (f *faultBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if err := matchFault(f.getFail, key); err != nil {
		return nil, err
	}
	return f.StorageBackend.Get(ctx, key)
}

func (f *faultBackend) Put(ctx context.Context, key string, value []byte) error {
	if err := matchFault(f.putFail, key); err != nil {
		return err
	}
	return f.StorageBackend.Put(ctx, key, value)
}

func (f *faultBackend) Delete(ctx context.Context, key string) error {
	if err := matchFault(f.deleteFail, key); err != nil {
		return err
	}
	return f.StorageBackend.Delete(ctx, key)
}

// testKeys gives the backend keys a store with the "trust/" prefix uses.
var testKeys = &BackendStore{prefix: "trust/"}

func putPEM(t *testing.T, backend xkms.StorageBackend, key string, raw []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	require.NoError(t, backend.Put(context.Background(), key, data))
}

func putMeta(t *testing.T, backend xkms.StorageBackend, fp string) {
	t.Helper()
	require.NoError(t, backend.Put(context.Background(), testKeys.metaKey(fp),
		[]byte(`{"fingerprint":"`+fp+`"}`)))
}

func TestBackendStore_NewBackendStore_ListFailure(t *testing.T) {
	backend := newFaultBackend()
	backend.listFail["trust/metadata/"] = errInjected

	store, err := NewBackendStore(backend, "trust/")
	require.Error(t, err)
	assert.Nil(t, store)
	assert.ErrorIs(t, err, ErrStorageRead)
	assert.ErrorContains(t, err, errInjected.Error())
}

func TestBackendStore_LoadSkipsUnusableMetadataEntries(t *testing.T) {
	backend := xkms.NewStorageMemory()
	ctx := context.Background()

	good := generateTestCert(t, "Good CA")
	goodFP := Fingerprint(good)
	putPEM(t, backend, testKeys.certKey(goodFP), good.Raw)
	putMeta(t, backend, goodFP)

	// Metadata that is not JSON.
	require.NoError(t, backend.Put(ctx, testKeys.metaKey(strings.Repeat("a", 64)), []byte("{not json")))

	// Metadata whose certificate entry is missing.
	putMeta(t, backend, strings.Repeat("b", 64))

	// Metadata whose certificate entry is not a certificate.
	corruptFP := strings.Repeat("c", 64)
	putMeta(t, backend, corruptFP)
	require.NoError(t, backend.Put(ctx, testKeys.certKey(corruptFP), []byte("garbage")))

	// Metadata whose certificate entry holds a different certificate.
	other := generateTestCert(t, "Other CA")
	swappedFP := strings.Repeat("d", 64)
	putMeta(t, backend, swappedFP)
	putPEM(t, backend, testKeys.certKey(swappedFP), other.Raw)

	store, err := NewBackendStore(backend, "trust/")
	require.NoError(t, err)
	defer store.Close()

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	contains, err := store.Contains(goodFP)
	require.NoError(t, err)
	assert.True(t, contains)
}

func TestBackendStore_LoadSkipsMetadataDeletedDuringLoad(t *testing.T) {
	backend := newFaultBackend()
	cert := generateTestCert(t, "Vanishing CA")
	fp := Fingerprint(cert)
	putPEM(t, backend, testKeys.certKey(fp), cert.Raw)
	putMeta(t, backend, fp)
	backend.getFail[testKeys.metaKey(fp)] = xkms.ErrStorageNotFound

	store, err := NewBackendStore(backend, "trust/")
	require.NoError(t, err)
	defer store.Close()

	// With no metadata loaded the store rebuilds from the certificate entry.
	contains, err := store.Contains(fp)
	require.NoError(t, err)
	assert.True(t, contains)
}

func TestBackendStore_LoadMetadataReadFailure(t *testing.T) {
	backend := newFaultBackend()
	cert := generateTestCert(t, "Unreadable CA")
	fp := Fingerprint(cert)
	putMeta(t, backend, fp)
	backend.getFail[testKeys.metaKey(fp)] = errInjected

	store, err := NewBackendStore(backend, "trust/")
	require.Error(t, err)
	assert.Nil(t, store)
	assert.ErrorIs(t, err, ErrStorageRead)
}

func TestBackendStore_RebuildListFailure(t *testing.T) {
	backend := newFaultBackend()
	backend.listFail["trust/certificates/"] = errInjected

	store, err := NewBackendStore(backend, "trust/")
	require.Error(t, err)
	assert.Nil(t, store)
	assert.ErrorIs(t, err, ErrStorageRead)
}

func TestBackendStore_RebuildSkipsUnusableCertificateEntries(t *testing.T) {
	backend := newFaultBackend()
	ctx := context.Background()

	good := generateTestCert(t, "Good CA")
	goodFP := Fingerprint(good)
	putPEM(t, backend, testKeys.certKey(goodFP), good.Raw)

	// A key that does not name a fingerprint.
	putPEM(t, backend, "trust/certificates/readme.pem", good.Raw)

	// An entry that is not a certificate.
	require.NoError(t, backend.Put(ctx, testKeys.certKey(strings.Repeat("a", 64)), []byte("garbage")))

	// An entry holding a certificate other than the one its key names.
	other := generateTestCert(t, "Other CA")
	putPEM(t, backend, testKeys.certKey(strings.Repeat("b", 64)), other.Raw)

	// Entries that vanish or cannot be read while the store rebuilds.
	vanished := generateTestCert(t, "Vanished CA")
	vanishedFP := Fingerprint(vanished)
	putPEM(t, backend, testKeys.certKey(vanishedFP), vanished.Raw)
	backend.getFail[testKeys.certKey(vanishedFP)] = xkms.ErrStorageNotFound
	unreadable := generateTestCert(t, "Unreadable CA")
	unreadableFP := Fingerprint(unreadable)
	putPEM(t, backend, testKeys.certKey(unreadableFP), unreadable.Raw)
	backend.getFail[testKeys.certKey(unreadableFP)] = errInjected

	store, err := NewBackendStore(backend, "trust/")
	require.NoError(t, err)
	defer store.Close()

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	contains, err := store.Contains(goodFP)
	require.NoError(t, err)
	assert.True(t, contains)
}

func TestBackendStore_RebuildReportsMetadataWriteFailure(t *testing.T) {
	backend := newFaultBackend()
	cert := generateTestCert(t, "Orphan CA")
	putPEM(t, backend, testKeys.certKey(Fingerprint(cert)), cert.Raw)
	backend.putFail["trust/metadata/"] = errInjected

	store, err := NewBackendStore(backend, "trust/")
	require.Error(t, err)
	assert.Nil(t, store)
	assert.ErrorIs(t, err, ErrStorageWrite)
}

func TestBackendStore_Reload_KeepsPreviousViewOnReadFailure(t *testing.T) {
	backend := newFaultBackend()
	store, err := NewBackendStore(backend, "trust/")
	require.NoError(t, err)
	defer store.Close()

	cert := generateTestCert(t, "Kept CA")
	require.NoError(t, store.AddCertificate(cert))

	backend.listFail["trust/metadata/"] = errInjected
	err = store.Reload()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStorageRead)

	contains, err := store.Contains(Fingerprint(cert))
	require.NoError(t, err)
	assert.True(t, contains)
}

func TestBackendStore_AddCertificate_StorageFailure(t *testing.T) {
	tests := []struct {
		name string
		add  func(*BackendStore, *x509.Certificate) error
	}{
		{"AddCertificate", func(s *BackendStore, c *x509.Certificate) error { return s.AddCertificate(c) }},
		{"AddCertificateWithOptions", func(s *BackendStore, c *x509.Certificate) error {
			return s.AddCertificateWithOptions(c, &AddCertificateOptions{Source: "test"})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/certificate write", func(t *testing.T) {
			backend := newFaultBackend()
			store, err := NewBackendStore(backend, "trust/")
			require.NoError(t, err)
			defer store.Close()
			backend.putFail["trust/certificates/"] = errInjected

			cert := generateTestCert(t, "Rejected CA")
			err = tt.add(store, cert)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrStorageWrite)
			contains, err := store.Contains(Fingerprint(cert))
			require.NoError(t, err)
			assert.False(t, contains)
		})
		t.Run(tt.name+"/metadata write rolls back the certificate", func(t *testing.T) {
			backend := newFaultBackend()
			store, err := NewBackendStore(backend, "trust/")
			require.NoError(t, err)
			defer store.Close()
			backend.putFail["trust/metadata/"] = errInjected

			cert := generateTestCert(t, "Rejected CA")
			fp := Fingerprint(cert)
			err = tt.add(store, cert)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrStorageWrite)
			contains, err := store.Contains(fp)
			require.NoError(t, err)
			assert.False(t, contains)
			_, err = backend.Get(context.Background(), testKeys.certKey(fp))
			assert.ErrorIs(t, err, xkms.ErrStorageNotFound)
		})
	}
}

func TestBackendStore_RemoveCertificate_StorageFailure(t *testing.T) {
	for _, prefix := range []string{"trust/certificates/", "trust/metadata/"} {
		t.Run(prefix, func(t *testing.T) {
			backend := newFaultBackend()
			store, err := NewBackendStore(backend, "trust/")
			require.NoError(t, err)
			defer store.Close()

			cert := generateTestCert(t, "Sticky CA")
			fp := Fingerprint(cert)
			require.NoError(t, store.AddCertificate(cert))
			backend.deleteFail[prefix] = errInjected

			err = store.RemoveCertificate(fp)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrStorageWrite)
			contains, err := store.Contains(fp)
			require.NoError(t, err)
			assert.True(t, contains)
		})
	}
}
