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

package server

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	acmeentities "github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	acmeobjstore "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/aeadnonce"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newQRDBTestServer builds a minimal *Server configured for embedded qrdb
// storage rooted at a temp dir, with the shared qrdb backend initialized.
func newQRDBTestServer(t *testing.T) *Server {
	t.Helper()

	s := &Server{
		config: &config.Config{
			Datastore: config.DatastoreConfig{Path: t.TempDir()},
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	require.NoError(t, s.initializeQRDBStorage())
	require.NotNil(t, s.qrdbStorage)
	return s
}

// TestCreateStorage_QRDBEmbeddedPutIfAbsent is the #61 regression.
//
// On a fresh embedded qrdb node the CA's first root-key store is a PutIfAbsent,
// and before go-qrdb v0.11 the standalone node wired no transaction service, so
// it failed with "TransactionServicer must not be nil" and the daemon died
// during boot ("failed to initialize CA ... put-if-absent ...: embedded:
// TransactionServicer must not be nil"). go-qrdb v0.11 (#62/#109) wires the
// standalone transaction service, so this exercises the exact path — a
// linearizable compare-and-swap through the embedded node — and asserts
// first-writer-wins. It runs against the CA-init key namespace deliberately.
func TestCreateStorage_QRDBEmbeddedPutIfAbsent(t *testing.T) {
	s := newQRDBTestServer(t)
	t.Cleanup(func() { _ = s.closeQRDBStorage() })

	ctx := context.Background()

	ca, err := s.createStorage("keys")
	require.NoError(t, err)

	const rootKey = "software:ca:Integration Test Root CA:ecdsa.key"

	stored, err := ca.PutIfAbsent(ctx, rootKey, []byte("key-material"))
	require.NoError(t, err, "#61: the standalone qrdb node must serve PutIfAbsent at boot")
	require.True(t, stored, "the first PutIfAbsent on an absent key must store it")

	stored2, err := ca.PutIfAbsent(ctx, rootKey, []byte("other-material"))
	require.NoError(t, err)
	require.False(t, stored2, "a second PutIfAbsent must report the key already present")

	got, err := ca.Get(ctx, rootKey)
	require.NoError(t, err)
	assert.Equal(t, []byte("key-material"), got, "the first writer's value must survive")
}

// TestCreateStorage_QRDBEmbeddedRoundTrip verifies that createStorage("qrdb")
// returns a working prefixed view over the shared embedded qrdb backend and
// that round-trip Put/Get succeeds.
func TestCreateStorage_QRDBEmbeddedRoundTrip(t *testing.T) {
	s := newQRDBTestServer(t)
	t.Cleanup(func() { _ = s.closeQRDBStorage() })

	ctx := context.Background()

	users, err := s.createStorage("users")
	require.NoError(t, err)
	require.NoError(t, users.Put(ctx, "alice", []byte("alice-value")))

	got, err := users.Get(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, []byte("alice-value"), got)
}

// TestDAOFactory_ServesTheOpenedDatabase proves daoFactory opens a database on
// the embedded datastore and the factory it returns serves a DAO over it.
func TestDAOFactory_ServesTheOpenedDatabase(t *testing.T) {
	s := newQRDBTestServer(t)
	s.ctx = context.Background()
	t.Cleanup(func() { _ = s.closeQRDBStorage() })

	daos, err := s.daoFactory(tpmpolicy.DatabaseName)
	require.NoError(t, err)
	registry, err := tpmpolicy.NewRegistry(daos)
	require.NoError(t, err)
	require.NoError(t, registry.PutScope(s.ctx, &tpmpolicy.Scope{Tenant: "acme", Mode: tpmpolicy.ModeShared}))
	scope, err := registry.Scope(s.ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, tpmpolicy.ModeShared, scope.Mode)
}

// TestDAOFactory_ReportsADatabaseThatCannotOpen proves a database the
// datastore refuses fails with *ErrStorageCreate carrying the cause.
func TestDAOFactory_ReportsADatabaseThatCannotOpen(t *testing.T) {
	s := newQRDBTestServer(t)
	s.ctx = context.Background()
	t.Cleanup(func() { _ = s.closeQRDBStorage() })

	daos, err := s.daoFactory("")
	assert.Nil(t, daos)
	var createErr *ErrStorageCreate
	require.ErrorAs(t, err, &createErr)
	assert.ErrorIs(t, err, datastore.ErrDatabaseNameRequired)
}

// TestDAOFactory_RefusesWithoutADatastore proves a feature that asks for its
// database before the datastore is open gets ErrNoDatastore, not a panic.
func TestDAOFactory_RefusesWithoutADatastore(t *testing.T) {
	s := &Server{ctx: context.Background()}

	daos, err := s.daoFactory(tpmpolicy.DatabaseName)
	assert.Nil(t, daos)
	assert.ErrorIs(t, err, ErrNoDatastore)
}

// TestFeatureDAOs_RunAsServicePrincipal proves every feature DAO the server
// builds over its embedded node -- the key-version, AEAD nonce, PKCS#11
// state, TPM policy and ACME stores, named databases and the default one --
// runs as the node's service principal through the datastore's one binding,
// though each call here carries no identity. The node enforces
// authentication: the same client in a datastore without the binding is
// refused.
func TestFeatureDAOs_RunAsServicePrincipal(t *testing.T) {
	s := &Server{
		ctx: context.Background(),
		config: &config.Config{
			Auth:      config.AuthConfig{Enabled: true},
			Datastore: config.DatastoreConfig{Path: t.TempDir()},
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	require.NoError(t, s.initializeQRDBStorage())
	t.Cleanup(func() { _ = s.closeQRDBStorage() })
	ctx := context.Background()

	require.NoError(t, s.initializeKeyVersionStore())
	rec := keyversion.Implicit("k", "software")
	rec.AddCurrent(2, time.Now(), "")
	require.NoError(t, s.keyVersions.Put(ctx, "acme", rec))
	_, found, err := s.keyVersions.Load(ctx, "acme", "software", "k")
	require.NoError(t, err)
	assert.True(t, found)

	daos, err := s.daoFactory(aeadnonce.DatabaseName)
	require.NoError(t, err)
	nonces, err := aeadnonce.NewStore(daos)
	require.NoError(t, err)
	claimed, err := nonces.ClaimNonce(ctx, []byte("entry"))
	require.NoError(t, err)
	assert.True(t, claimed)

	require.NoError(t, s.initializePKCS11StateStore())
	stored, err := s.pkcs11StateStore.PutIfAbsent(ctx, "acme", "token", "k", []byte("v"))
	require.NoError(t, err)
	assert.True(t, stored)
	keys, err := s.pkcs11StateStore.List(ctx, "acme", "token", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"k"}, keys)

	daos, err = s.daoFactory(tpmpolicy.DatabaseName)
	require.NoError(t, err)
	registry, err := tpmpolicy.NewRegistry(daos)
	require.NoError(t, err)
	require.NoError(t, registry.PutScope(ctx, &tpmpolicy.Scope{Tenant: "acme", Mode: tpmpolicy.ModeShared}))
	_, err = registry.Scope(ctx, "acme")
	require.NoError(t, err)

	acmeStores, err := acmeobjstore.NewFactory(s.datastore.DAOFactory())
	require.NoError(t, err)
	accounts, err := acmeStores.AccountDAO()
	require.NoError(t, err)
	require.NoError(t, accounts.Save(ctx, &acmeentities.ACMEAccount{ID: 7, Status: "valid"}))
	account, err := accounts.Get(ctx, 7)
	require.NoError(t, err)
	assert.Equal(t, "valid", account.Status)

	unbound, err := datastore.New(s.qrdbClient, s.config.Datastore)
	require.NoError(t, err)
	_, err = unbound.DatabaseKVStore(ctx, "unbound")
	assert.ErrorIs(t, err, qrdbsdk.ErrUnauthenticated)
}

// TestCreateStorage_QRDBNamespaceIsolation verifies that two subdir views over
// the same shared qrdb backend are isolated: a key written to one namespace is
// not visible via another namespace's prefixed view.
func TestCreateStorage_QRDBNamespaceIsolation(t *testing.T) {
	s := newQRDBTestServer(t)
	t.Cleanup(func() { _ = s.closeQRDBStorage() })

	ctx := context.Background()

	users, err := s.createStorage("users")
	require.NoError(t, err)
	caView, err := s.createStorage("ca")
	require.NoError(t, err)

	// Same logical key in each namespace, different values.
	require.NoError(t, users.Put(ctx, "shared-key", []byte("from-users")))
	require.NoError(t, caView.Put(ctx, "shared-key", []byte("from-ca")))

	uVal, err := users.Get(ctx, "shared-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("from-users"), uVal)

	cVal, err := caView.Get(ctx, "shared-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("from-ca"), cVal)

	// A key written only to "users" must not be visible via the "ca" view.
	// The qrdb node KV returns storage.ErrNotFound for a missing key (the
	// single, consistent backend contract; qrdb's sentinel is aligned to
	// storage.ErrNotFound), so isolation is asserted via the not-found error
	// and via List, which is correctly prefix-scoped.
	require.NoError(t, users.Put(ctx, "users-only", []byte("secret")))

	_, err = caView.Get(ctx, "users-only")
	require.ErrorIs(t, err, storage.ErrNotFound, "users-only must not be readable via the ca namespace")

	usersHit, err := users.Get(ctx, "users-only")
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), usersHit)

	// List in each namespace returns only that namespace's keys (prefix stripped).
	// This is the authoritative isolation signal: the ca namespace must not
	// enumerate any users-namespace key.
	userKeys, err := users.List(ctx, "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"shared-key", "users-only"}, userKeys)

	caKeys, err := caView.List(ctx, "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"shared-key"}, caKeys)
	assert.NotContains(t, caKeys, "users-only")
}

// TestCreateStorage_QRDBPrefixViewCloseDoesNotBreakSharedBackend verifies the
// ownership contract: closing one prefixed view is a no-op on the shared inner
// backend, so other views and the shared backend keep working.
func TestCreateStorage_QRDBPrefixViewCloseDoesNotBreakSharedBackend(t *testing.T) {
	s := newQRDBTestServer(t)
	t.Cleanup(func() { _ = s.closeQRDBStorage() })

	ctx := context.Background()

	users, err := s.createStorage("users")
	require.NoError(t, err)
	caView, err := s.createStorage("ca")
	require.NoError(t, err)

	require.NoError(t, users.Put(ctx, "k", []byte("u")))
	require.NoError(t, caView.Put(ctx, "k", []byte("c")))

	// Closing the users view must not tear down the shared backend.
	require.NoError(t, users.Close())

	// The ca view still works after the users view was closed.
	cVal, err := caView.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("c"), cVal)

	// And the users view itself still reads, because Close was a no-op on inner.
	uVal, err := users.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("u"), uVal)
}

// TestCreateStorageAt_QRDBDerivesPrefixFromBase verifies that createStorageAt
// derives a qrdb key namespace from the final path segment and round-trips.
func TestCreateStorageAt_QRDBDerivesPrefixFromBase(t *testing.T) {
	s := newQRDBTestServer(t)
	t.Cleanup(func() { _ = s.closeQRDBStorage() })

	ctx := context.Background()

	soft, err := s.createStorageAt("/var/lib/xkms/software")
	require.NoError(t, err)
	pkcs8View, err := s.createStorageAt("/var/lib/xkms/pkcs8")
	require.NoError(t, err)

	require.NoError(t, soft.Put(ctx, "key1", []byte("soft")))
	require.NoError(t, pkcs8View.Put(ctx, "key1", []byte("pkcs8")))

	sVal, err := soft.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("soft"), sVal)

	// Namespaces are isolated by base segment.
	_, err = pkcs8View.Get(ctx, "key1")
	require.NoError(t, err)
	pVal, err := pkcs8View.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("pkcs8"), pVal)

	assert.NotEqual(t, sVal, pVal)
}

// TestInitializeQRDBStorage_NonQRDBBackendNoop and
// TestInitializeQRDBStorage_UnsupportedTransport used to prove
// initializeQRDBStorage was a no-op for a non-"qrdb" storage.backend, and
// rejected an unknown storage.qrdb.transport. Neither branch exists anymore:
// initializeQRDBStorage always builds the one shared datastore now, in
// either "standalone" or "remote" mode (go-xkms#1345). The remaining,
// reachable transport-rejection path is exercised directly by
// TestDialRemote_UnsupportedTransport (pkg/datastore/remote_test.go)
// and end to end by TestInitializeQRDBStorage_InvalidTransport
// (server_extra_test.go).

// TestCloseQRDBStorage_Idempotent verifies closeQRDBStorage can be called
// multiple times safely.
func TestCloseQRDBStorage_Idempotent(t *testing.T) {
	s := newQRDBTestServer(t)

	require.NoError(t, s.closeQRDBStorage())
	assert.Nil(t, s.qrdbStorage)
	// Second call is a no-op.
	require.NoError(t, s.closeQRDBStorage())
}
