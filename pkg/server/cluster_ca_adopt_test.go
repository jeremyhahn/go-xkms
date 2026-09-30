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

package server

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
)

// adoptStagedTestServer builds a minimal *Server whose Storage.Path is a
// fresh temp dir, matching what adoptStagedClusterCACerts derives the staged
// path from (clusterCACacheSubdir under storage.path).
func adoptStagedTestServer(t *testing.T) *Server {
	t.Helper()
	return newMinimalServer(t, &config.Config{
		Datastore: config.DatastoreConfig{Engine: "memory", Path: t.TempDir()},
	})
}

// writeStagedCACerts writes certs, PEM-encoded, to the path
// adoptStagedClusterCACerts reads (StagedCACertsPath under
// clusterCACacheSubdir), creating the parent directory as needed.
func writeStagedCACerts(t *testing.T, s *Server, pemBytes []byte) {
	t.Helper()
	path := clusterca.StagedCACertsPath(filepath.Join(s.config.Datastore.Path, clusterCACacheSubdir))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
}

// TestAdoptStagedClusterCACerts_NoStagedFile proves the documented no-op:
// no pre-staged material (the normal case for every non-cluster-ACME
// deployment) must not fail initializeCA's unconditional call.
func TestAdoptStagedClusterCACerts_NoStagedFile(t *testing.T) {
	s := adoptStagedTestServer(t)
	cs := newInMemoryCertStoreForAdopt(t)

	require.NoError(t, s.adoptStagedClusterCACerts(cs))
}

// TestAdoptStagedClusterCACerts_ImportsStagedCertificates proves that every
// CERTIFICATE PEM block in the staged file lands in the runtime CA's
// certificate store.
func TestAdoptStagedClusterCACerts_ImportsStagedCertificates(t *testing.T) {
	s := adoptStagedTestServer(t)
	cs := newInMemoryCertStoreForAdopt(t)

	root := selfSignedCert(t)
	writeStagedCACerts(t, s, encodeCertPEM(t, root))

	require.NoError(t, s.adoptStagedClusterCACerts(cs))

	got, err := cs.GetCertificate(root.Subject.CommonName)
	require.NoError(t, err)
	assert.Equal(t, root.Raw, got.Raw)
}

// TestAdoptStagedClusterCACerts_DuplicateIsToleratedNotFatal proves that a
// certificate already present in the runtime store (adoption on a later
// boot after a prior boot already adopted it) is logged and skipped rather
// than failing initializeCA.
func TestAdoptStagedClusterCACerts_DuplicateIsToleratedNotFatal(t *testing.T) {
	s := adoptStagedTestServer(t)
	cs := newInMemoryCertStoreForAdopt(t)

	root := selfSignedCert(t)
	require.NoError(t, cs.StoreCertificate(root))
	writeStagedCACerts(t, s, encodeCertPEM(t, root))

	require.NoError(t, s.adoptStagedClusterCACerts(cs))
}

// TestAdoptStagedClusterCACerts_MultipleCertificates proves a staged file
// carrying more than one certificate (root + intermediate) imports all of
// them, matching Load's requirement to find the full hierarchy.
func TestAdoptStagedClusterCACerts_MultipleCertificates(t *testing.T) {
	s := adoptStagedTestServer(t)
	cs := newInMemoryCertStoreForAdopt(t)

	root := selfSignedCert(t)
	intermediate := selfSignedCert(t)
	pemBytes := append(encodeCertPEM(t, root), encodeCertPEM(t, intermediate)...)
	writeStagedCACerts(t, s, pemBytes)

	require.NoError(t, s.adoptStagedClusterCACerts(cs))

	_, err := cs.GetCertificate(root.Subject.CommonName)
	require.NoError(t, err)
	_, err = cs.GetCertificate(intermediate.Subject.CommonName)
	require.NoError(t, err)
}

// TestAdoptStagedClusterCACerts_MalformedCertificateFailsClosed proves a
// staged file whose CERTIFICATE block cannot be parsed as X.509 surfaces the
// parse error rather than silently skipping the corrupt entry.
func TestAdoptStagedClusterCACerts_MalformedCertificateFailsClosed(t *testing.T) {
	s := adoptStagedTestServer(t)
	cs := newInMemoryCertStoreForAdopt(t)

	badPEM := []byte("-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----\n")
	writeStagedCACerts(t, s, badPEM)

	err := s.adoptStagedClusterCACerts(cs)
	require.Error(t, err)
}

// newInMemoryCertStoreForAdopt builds an in-memory CertStore, matching the
// production wiring in initializeCA (storage.NewCertAdapter over the
// configured storage backend), so these tests exercise the real
// certstore.CertStore.StoreCertificate/GetCertificate path.
func newInMemoryCertStoreForAdopt(t *testing.T) certstore.CertStore {
	t.Helper()
	memBackend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(memBackend),
	})
	require.NoError(t, err)
	return cs
}

// encodeCertPEM PEM-encodes a certificate as a CERTIFICATE block.
func encodeCertPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
