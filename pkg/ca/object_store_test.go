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

package ca

import (
	"crypto/x509"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbstorage "github.com/jeremyhahn/go-qrdb/sdk/go/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// errObjectStoreTest is the failure failingObjectStore injects.
var errObjectStoreTest = errors.New("object_store_test: simulated storage failure")

// failingObjectStore decorates a go-qrdb storage so every read, write and
// listing fails with errObjectStoreTest.
type failingObjectStore struct {
	qrdbstorage.Storage
}

func (s *failingObjectStore) Get([]byte) ([]byte, error)    { return nil, errObjectStoreTest }
func (s *failingObjectStore) Set([]byte, []byte) error      { return errObjectStoreTest }
func (s *failingObjectStore) List([]byte) ([][]byte, error) { return nil, errObjectStoreTest }
func (s *failingObjectStore) Exists([]byte) (bool, error)   { return false, errObjectStoreTest }

func setupTestCAWithFailingObjectStore(t *testing.T) *CA {
	t.Helper()
	ca := setupTestCA(t)
	ca.objectStore = &failingObjectStore{Storage: qrdbstorage.NewMemoryStorage()}
	return ca
}

func TestObjectStore_RoundTrip(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)

	require.NoError(t, ca.putObject("blobs/a", []byte("alpha")))
	require.NoError(t, ca.putObject("blobs/b", []byte("beta")))
	require.NoError(t, ca.putObject("other/c", []byte("gamma")))

	data, err := ca.getObject("blobs/a")
	require.NoError(t, err)
	require.Equal(t, []byte("alpha"), data)

	keys, err := ca.listObjects("blobs/")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"blobs/a", "blobs/b"}, keys)
}

func TestObjectStore_GetMissingKeyIsNotFound(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)

	_, err := ca.getObject("blobs/missing")
	require.ErrorIs(t, err, ErrObjectNotFound)
	require.NotErrorIs(t, err, ErrStorageError)
}

func TestObjectStore_StorageFailuresAreStorageErrors(t *testing.T) {
	ca := setupTestCAWithFailingObjectStore(t)

	_, err := ca.getObject("blobs/a")
	require.ErrorIs(t, err, ErrStorageError)
	require.ErrorContains(t, err, errObjectStoreTest.Error())

	err = ca.putObject("blobs/a", []byte("alpha"))
	require.ErrorIs(t, err, ErrStorageError)

	_, err = ca.listObjects("blobs/")
	require.ErrorIs(t, err, ErrStorageError)
}

func TestBlob_RoundTripAndMissing(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)

	require.NoError(t, ca.ImportBlob([]byte("raw/key"), []byte("payload")))
	data, err := ca.Blob([]byte("raw/key"))
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), data)

	_, err = ca.Blob([]byte("raw/missing"))
	require.ErrorIs(t, err, ErrObjectNotFound)
}

func TestCrossSignedPEM_ListFailureSurfaces(t *testing.T) {
	ca := setupTestCAWithFailingObjectStore(t)

	_, err := ca.CrossSignedPEM(&types.KeyAttributes{CN: "leaf"})
	require.ErrorIs(t, err, ErrStorageError)
}

func TestGetXSignedCertificates_ListFailureYieldsNativeChainOnly(t *testing.T) {
	ca := setupTestCAWithFailingObjectStore(t)

	require.Nil(t, ca.getXSignedCertificates("leaf"))
}

func TestImportDistributionCRLs_LookupFailureSurfaces(t *testing.T) {
	ca := setupTestCAWithFailingObjectStore(t)
	cert := &x509.Certificate{CRLDistributionPoints: []string{"https://crl.example.com/ca.crl"}}

	err := ca.ImportDistributionCRLs(cert)
	require.ErrorIs(t, err, ErrStorageError)
}
