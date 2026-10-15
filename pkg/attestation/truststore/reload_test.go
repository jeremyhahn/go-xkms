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
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// A trust store's cache is populated once at construction. Two processes — the
// GUI and the CLI — hold separate stores over the same backing data, so one
// never sees the other's changes without an explicit reload.
//
// These tests use two stores over one backend as a stand-in for two processes.

// TestReloadSeesACertificateAddedByAnotherProcess is the reported symptom: a
// certificate imported by the CLI while the GUI runs stays invisible until
// restart, and a freshly imported CA is exactly what a user adds and then
// expects to work.
func TestReloadSeesACertificateAddedByAnotherProcess(t *testing.T) {
	backend := storage.NewMemory()

	gui, err := NewBackendStore(backend, "trust/")
	require.NoError(t, err)
	defer func() { _ = gui.Close() }()

	cli, err := NewBackendStore(backend, "trust/")
	require.NoError(t, err)
	defer func() { _ = cli.Close() }()

	cert := generateTestCert(t, "added-by-cli")
	require.NoError(t, cli.AddCertificate(cert))

	// Precondition: the GUI's cache predates the write, so it cannot see it.
	before, err := gui.Count()
	require.NoError(t, err)
	require.Zero(t, before, "precondition: the second store has not reloaded yet")

	require.NoError(t, gui.Reload())

	after, err := gui.Count()
	require.NoError(t, err)
	require.Equal(t, 1, after, "reload must surface a certificate added elsewhere")

	has, err := gui.Contains(Fingerprint(cert))
	require.NoError(t, err)
	require.True(t, has)
}

// TestReloadDropsACertificateRemovedByAnotherProcess is the half that matters
// more. A merge would leave the store trusting an anchor the operator revoked —
// worse than not seeing a new one, because it is a trust decision made on data
// known to be wrong.
func TestReloadDropsACertificateRemovedByAnotherProcess(t *testing.T) {
	backend := storage.NewMemory()

	seed, err := NewBackendStore(backend, "trust/")
	require.NoError(t, err)
	cert := generateTestCert(t, "later-revoked")
	require.NoError(t, seed.AddCertificate(cert))
	require.NoError(t, seed.Close())

	gui, err := NewBackendStore(backend, "trust/")
	require.NoError(t, err)
	defer func() { _ = gui.Close() }()

	cli, err := NewBackendStore(backend, "trust/")
	require.NoError(t, err)
	defer func() { _ = cli.Close() }()

	require.NoError(t, cli.RemoveCertificate(Fingerprint(cert)))

	require.NoError(t, gui.Reload())

	has, err := gui.Contains(Fingerprint(cert))
	require.NoError(t, err)
	require.False(t, has, "a certificate removed elsewhere must stop being trusted here")

	count, err := gui.Count()
	require.NoError(t, err)
	require.Zero(t, count)
}

// TestReloadRebuildsTheCertPool proves the cached pool is invalidated too.
// Leaving a stale pool would keep the removed anchor in every chain
// verification even after the listing showed it gone — the listing and the
// trust decision must not disagree.
//
// The pool is compared with CertPool.Equal rather than enumerated with
// Subjects. Subjects is deprecated because it UNDER-REPORTS for a pool derived
// from SystemCertPool, and an assertion that can see less than the pool holds
// is a weak guard on precisely the property being pinned here: it would pass
// while the pool still carried the anchor the test says was dropped.
func TestReloadRebuildsTheCertPool(t *testing.T) {
	backend := storage.NewMemory()

	seed, err := NewBackendStore(backend, "trust/")
	require.NoError(t, err)
	cert := generateTestCert(t, "pooled")
	require.NoError(t, seed.AddCertificate(cert))
	require.NoError(t, seed.Close())

	gui, err := NewBackendStore(backend, "trust/")
	require.NoError(t, err)
	defer func() { _ = gui.Close() }()

	withCert := x509.NewCertPool()
	withCert.AddCert(cert)

	pool, err := gui.CertPool()
	require.NoError(t, err)
	require.True(t, pool.Equal(withCert),
		"precondition: the pool is built and cached holding the certificate")

	cli, err := NewBackendStore(backend, "trust/")
	require.NoError(t, err)
	defer func() { _ = cli.Close() }()
	require.NoError(t, cli.RemoveCertificate(Fingerprint(cert)))

	require.NoError(t, gui.Reload())

	pool, err = gui.CertPool()
	require.NoError(t, err)
	require.True(t, pool.Equal(x509.NewCertPool()),
		"the cached pool must be rebuilt, not served stale, after a reload")
}

// TestReloadRefusesAfterClose proves a closed store reports rather than
// silently doing nothing.
func TestReloadRefusesAfterClose(t *testing.T) {
	backend := storage.NewMemory()

	store, err := NewBackendStore(backend, "trust/")
	require.NoError(t, err)
	require.NoError(t, store.Close())

	require.ErrorIs(t, store.Reload(), ErrStoreClosed)
}

// TestFileStoreReloadSeesAnotherProcessesWrite covers the second implementer.
// The two stores share a directory the way two processes would.
func TestFileStoreReloadSeesAnotherProcessesWrite(t *testing.T) {
	dir := t.TempDir()

	gui, err := NewFileStore(&FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer func() { _ = gui.Close() }()

	cli, err := NewFileStore(&FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer func() { _ = cli.Close() }()

	cert := generateTestCert(t, "file-added-by-cli")
	require.NoError(t, cli.AddCertificate(cert))

	before, err := gui.Count()
	require.NoError(t, err)
	require.Zero(t, before, "precondition: the second store has not reloaded yet")

	require.NoError(t, gui.Reload())

	after, err := gui.Count()
	require.NoError(t, err)
	require.Equal(t, 1, after, "reload must surface a certificate added elsewhere")
}

// TestFileStoreReloadRefusesAfterClose mirrors the backend store's refusal.
func TestFileStoreReloadRefusesAfterClose(t *testing.T) {
	store, err := NewFileStore(&FileStoreConfig{BaseDir: t.TempDir()})
	require.NoError(t, err)
	require.NoError(t, store.Close())

	require.ErrorIs(t, store.Reload(), ErrStoreClosed)
}
