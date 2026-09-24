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

package secretservice

import (
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDaemon_CreateCollection_StoreFailure covers CreateFolder's error
// branch, which no existing test reaches (every other CreateCollection test
// either creates the default folder, which never calls CreateFolder, or
// succeeds outright).
func TestDaemon_CreateCollection_StoreFailure(t *testing.T) {
	store := newErrStore()
	store.createFolderErr = errStoreUnavailable
	d := newBusDaemon(t, store).Daemon

	_, _, dbusErr := d.CreateCollection(map[string]dbus.Variant{
		"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant("Work"),
	}, "")
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errStoreUnavailable.Error())
}

// TestDaemon_CreateCollection_AliasPersistenceFailureIsNotFatal proves a
// failure to persist an alias (a best-effort warn-logged path) never fails
// CreateCollection itself: the collection was created either way.
func TestDaemon_CreateCollection_AliasPersistenceFailureIsNotFatal(t *testing.T) {
	store := newErrStore()
	store.setAliasErr = errStoreUnavailable
	d := newBusDaemon(t, store).Daemon

	collectionPath, promptPath, dbusErr := d.CreateCollection(nil, "custom")
	require.Nil(t, dbusErr)
	assert.Equal(t, dbus.ObjectPath("/"), promptPath)
	assert.Equal(t, d.mapper.CollectionPathFromFolder("custom"), collectionPath)
}

// TestDaemon_CreateCollection_AuditWriteFailureFailsTheCall covers the
// success-path audit write failure, which none of the alias/label-mapping
// tests in service_dbus_test.go install a failing logger for.
func TestDaemon_CreateCollection_AuditWriteFailureFailsTheCall(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon
	d.SetAuditLogger(failingAuditLogger{})

	_, _, dbusErr := d.CreateCollection(map[string]dbus.Variant{
		"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant("Work"),
	}, "")
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
}

// TestDaemon_CreateCollection_WhileSealed_AuditWriteFailureFailsTheCall
// covers the sealed-branch's own audit write, distinct from the
// unsealed/success one above.
func TestDaemon_CreateCollection_WhileSealed_AuditWriteFailureFailsTheCall(t *testing.T) {
	barrier := newTestBarrier(t)
	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	require.NoError(t, barrier.Seal())
	d.SetAuditLogger(failingAuditLogger{})

	_, _, dbusErr := d.CreateCollection(nil, "custom")
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
}

// TestDaemon_SearchItems_WhileSealed_AuditWriteFailureFailsTheCall and
// TestDaemon_SearchItems_AuditWriteFailureFailsTheCall cover the
// Service-level SearchItems' two audit call sites the existing
// StoreFailure/success tests in service_test.go and service_dbus_test.go
// do not.
func TestDaemon_SearchItems_WhileSealed_AuditWriteFailureFailsTheCall(t *testing.T) {
	barrier := newTestBarrier(t)
	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	require.NoError(t, barrier.Seal())
	d.SetAuditLogger(failingAuditLogger{})

	_, _, dbusErr := d.SearchItems(map[string]string{})
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
}

func TestDaemon_SearchItems_StoreFailure_ViaErrStore(t *testing.T) {
	store := newErrStore()
	store.listErr = errStoreUnavailable
	d := newBusDaemon(t, store).Daemon

	_, _, dbusErr := d.SearchItems(map[string]string{})
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errStoreUnavailable.Error())
}

func TestDaemon_SearchItems_AuditWriteFailureFailsTheCall(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon
	d.SetAuditLogger(failingAuditLogger{})

	_, _, dbusErr := d.SearchItems(map[string]string{})
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
}

// TestDaemon_SetAlias_StoreFailure covers as.SetAlias's own error return,
// distinct from CreateCollection's best-effort warn-and-continue handling
// of the same failure.
func TestDaemon_SetAlias_StoreFailure(t *testing.T) {
	store := newErrStore()
	store.setAliasErr = errStoreUnavailable
	d := newBusDaemon(t, store).Daemon

	dbusErr := d.SetAlias("custom", d.mapper.CollectionPathFromFolder("Work"))
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errStoreUnavailable.Error())
}

// TestDaemon_CloseSession_AuditWriteFailureFailsTheCall covers
// CloseSession's audit write, which no existing test installs a failing
// logger for.
func TestDaemon_CloseSession_AuditWriteFailureFailsTheCall(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon

	_, sessionPath, dbusErr := d.OpenSession(testSender, AlgorithmPlain, dbus.MakeVariant(""))
	require.Nil(t, dbusErr)

	d.SetAuditLogger(failingAuditLogger{})
	closeErr := d.CloseSession(sessionPath)
	require.NotNil(t, closeErr)
	assert.Contains(t, closeErr.Error(), errAuditSinkDown.Error())
}

// TestDaemon_DecryptSecret_DH proves decryptSecret's DH branch actually
// decrypts, not just that it exists: the plain-session case is already
// covered in service_test.go's TestDaemon_DecryptSecret.
func TestDaemon_DecryptSecret_DH(t *testing.T) {
	daemon, err := NewDaemon(newMemoryStore(), newTestBarrier(t), nil, nil)
	require.NoError(t, err)

	serverKeys, err := GenerateDHKeyPair()
	require.NoError(t, err)
	clientKeys, err := GenerateDHKeyPair()
	require.NoError(t, err)
	shared := ComputeSharedSecret(serverKeys.Private, clientKeys.Public)
	aesKey := DeriveAESKey(shared)

	sessionPath := daemon.mapper.SessionPath("dh")
	daemon.sessionsMu.Lock()
	daemon.sessions[sessionPath] = &SessionInfo{Path: sessionPath, Algorithm: AlgorithmDH, AESKey: aesKey}
	daemon.sessionsMu.Unlock()

	crypto := NewSessionCryptoFromKey(aesKey)
	iv, ciphertext, err := crypto.Encrypt([]byte("s3cret-value"))
	require.NoError(t, err)

	value, err := daemon.decryptSecret(SecretStruct{Session: sessionPath, Parameters: iv, Value: ciphertext})
	require.NoError(t, err)
	assert.Equal(t, "s3cret-value", string(value))
}
