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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func testSecret(t *testing.T, d *Daemon, plaintext string) SecretStruct {
	t.Helper()
	_, sessionPath, dbusErr := d.OpenSession(testSender, AlgorithmPlain, dbus.MakeVariant(""))
	require.Nil(t, dbusErr)
	return SecretStruct{Session: sessionPath, Value: []byte(plaintext), ContentType: "text/plain; charset=utf8"}
}

func TestCollection_CreateItem(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}

	t.Run("success", func(t *testing.T) {
		secret := testSecret(t, d, "s3cret")
		props := map[string]dbus.Variant{
			"org.freedesktop.Secret.Item.Label":      dbus.MakeVariant("GitHub"),
			"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(map[string]string{"host": "github.com"}),
		}

		itemPath, promptPath, dbusErr := c.CreateItem(props, secret, false)
		require.Nil(t, dbusErr)
		assert.Equal(t, dbus.ObjectPath("/"), promptPath)
		assert.Contains(t, string(itemPath), string(collectionPath))

		pw, getErr := d.store.Get(xkms.GenerateStaticPasswordID("GitHub", "Work"))
		require.NoError(t, getErr)
		assert.Equal(t, "s3cret", pw.Password)
		assert.Equal(t, "github.com", pw.Attributes["host"])
	})

	t.Run("missing_label_is_refused", func(t *testing.T) {
		secret := testSecret(t, d, "s3cret")
		_, _, dbusErr := c.CreateItem(map[string]dbus.Variant{}, secret, false)
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrLabelRequired.Error())
	})
}

func TestCollection_CreateItem_WhileSealedRefuses(t *testing.T) {
	barrier := newTestBarrier(t)
	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}
	require.NoError(t, barrier.Seal())

	secret := SecretStruct{Session: "/no/such/session"}
	_, _, dbusErr := c.CreateItem(map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("GitHub"),
	}, secret, false)
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), ErrCollectionLocked.Error())
}

func TestCollection_SearchItems(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)

	require.NoError(t, store.Add(&xkms.StaticPassword{Name: "GitHub", FolderPath: "Work", Password: "s3cret"}))
	require.NoError(t, store.Add(&xkms.StaticPassword{Name: "Other", FolderPath: "Personal", Password: "s3cret2"}))

	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}

	t.Run("finds_items_in_this_folder_only", func(t *testing.T) {
		results, dbusErr := c.SearchItems(map[string]string{"service": "GitHub"})
		require.Nil(t, dbusErr)
		require.Len(t, results, 1)
	})

	t.Run("does_not_leak_other_collections", func(t *testing.T) {
		results, dbusErr := c.SearchItems(map[string]string{"service": "Other"})
		require.Nil(t, dbusErr)
		assert.Empty(t, results)
	})
}

func TestCollection_Delete(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)

	require.NoError(t, store.Add(&xkms.StaticPassword{Name: "GitHub", FolderPath: "Work", Password: "s3cret"}))
	require.NoError(t, store.CreateFolder("Work"))

	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}

	t.Run("success", func(t *testing.T) {
		promptPath, dbusErr := c.Delete()
		require.Nil(t, dbusErr)
		assert.Equal(t, dbus.ObjectPath("/"), promptPath)

		items, listErr := store.ListByFolderDirect("Work")
		require.NoError(t, listErr)
		assert.Empty(t, items)
	})

	t.Run("while_sealed_refuses", func(t *testing.T) {
		require.NoError(t, d.barrier.Seal())
		defer func() { require.NoError(t, d.barrier.Unseal(d.ctx, testCredentials(t))) }()

		_, dbusErr := c.Delete()
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrCollectionLocked.Error())
	})
}

func TestCollection_Properties(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	require.NoError(t, store.Add(&xkms.StaticPassword{Name: "GitHub", FolderPath: "Work", Password: "s3cret"}))

	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}

	t.Run("get_all_unlocked", func(t *testing.T) {
		props, dbusErr := c.GetAll(CollectionInterface)
		require.Nil(t, dbusErr)
		assert.Equal(t, false, props["Locked"].Value())
		assert.Equal(t, "Work", props["Label"].Value())
		items, ok := props["Items"].Value().([]dbus.ObjectPath)
		require.True(t, ok)
		assert.Len(t, items, 1)
	})

	t.Run("get_all_wrong_interface", func(t *testing.T) {
		_, dbusErr := c.GetAll("org.freedesktop.Secret.Item")
		require.NotNil(t, dbusErr)
	})

	t.Run("get_single_property", func(t *testing.T) {
		v, dbusErr := c.Get(CollectionInterface, "Label")
		require.Nil(t, dbusErr)
		assert.Equal(t, "Work", v.Value())
	})

	t.Run("get_wrong_interface", func(t *testing.T) {
		_, dbusErr := c.Get("org.freedesktop.Secret.Item", "Label")
		require.NotNil(t, dbusErr)
	})

	t.Run("get_unknown_property", func(t *testing.T) {
		_, dbusErr := c.Get(CollectionInterface, "Bogus")
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrPropertyNotFound.Error())
	})

	t.Run("get_all_while_sealed_never_lists_items", func(t *testing.T) {
		require.NoError(t, d.barrier.Seal())
		defer func() { require.NoError(t, d.barrier.Unseal(d.ctx, testCredentials(t))) }()

		props, dbusErr := c.GetAll(CollectionInterface)
		require.Nil(t, dbusErr)
		assert.Equal(t, true, props["Locked"].Value())
		items, ok := props["Items"].Value().([]dbus.ObjectPath)
		require.True(t, ok)
		assert.Empty(t, items)
	})

	t.Run("set_label_is_read_only", func(t *testing.T) {
		dbusErr := c.Set(CollectionInterface, "Label", dbus.MakeVariant("renamed"))
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrPropertyReadOnly.Error())
	})

	t.Run("set_unknown_property", func(t *testing.T) {
		dbusErr := c.Set(CollectionInterface, "Bogus", dbus.MakeVariant("x"))
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrPropertyNotFound.Error())
	})
}

// TestCollection_Properties_DefaultFolderLabel covers label()'s other branch:
// TestCollection_Properties above always addresses a named folder, so the
// root folder's alias name was never exercised.
func TestCollection_Properties_DefaultFolderLabel(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	collectionPath, err := d.exportCollection("")
	require.NoError(t, err)

	c := &collectionObject{daemon: d, path: collectionPath, folder: ""}

	v, dbusErr := c.Get(CollectionInterface, "Label")
	require.Nil(t, dbusErr)
	assert.Equal(t, DefaultCollection, v.Value())
}

// testCredentials returns the credentials matching newTestBarrier's
// passphrase, for tests that need to re-unseal after sealing mid-test.
func testCredentials(t *testing.T) xkms.SealCredentials {
	t.Helper()
	creds, err := xkms.CredentialsFor([]byte("test-barrier-password-12345"))
	require.NoError(t, err)
	return creds
}

func TestCollection_Delete_StoreFailures(t *testing.T) {
	t.Run("list_by_folder_direct_fails", func(t *testing.T) {
		store := newErrStore()
		store.listByFolderDirectErr = errStoreUnavailable
		d := newBusDaemon(t, store).Daemon
		collectionPath, err := d.exportCollection("Work")
		require.NoError(t, err)
		c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}

		_, dbusErr := c.Delete()
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), errStoreUnavailable.Error())
	})

	t.Run("remove_folder_fails", func(t *testing.T) {
		store := newErrStore()
		store.removeFolderErr = errStoreUnavailable
		require.NoError(t, store.Add(&xkms.StaticPassword{Name: "GitHub", FolderPath: "Work", Password: "s3cret"}))
		d := newBusDaemon(t, store).Daemon
		collectionPath, err := d.exportCollection("Work")
		require.NoError(t, err)
		c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}

		_, dbusErr := c.Delete()
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), errStoreUnavailable.Error())
	})
}

// TestCollection_Delete_WhileSealed_AuditWriteFailureFailsTheCall covers
// the sealed-branch's own audit write, distinct from
// TestCollection_Delete_AuditWriteFailureFailsTheCall's success-path one.
func TestCollection_Delete_WhileSealed_AuditWriteFailureFailsTheCall(t *testing.T) {
	barrier := newTestBarrier(t)
	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}
	require.NoError(t, barrier.Seal())
	d.SetAuditLogger(failingAuditLogger{})

	_, dbusErr := c.Delete()
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
}

func TestCollection_Delete_AuditWriteFailureFailsTheCall(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}
	d.SetAuditLogger(failingAuditLogger{})

	_, dbusErr := c.Delete()
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
}

func TestCollection_SearchItems_WhileSealed(t *testing.T) {
	barrier := newTestBarrier(t)
	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}
	require.NoError(t, barrier.Seal())

	results, dbusErr := c.SearchItems(map[string]string{})
	require.NotNil(t, dbusErr)
	assert.Nil(t, results)
	assert.Contains(t, dbusErr.Error(), ErrCollectionLocked.Error())
}

func TestCollection_SearchItems_WhileSealed_AuditWriteFailureFailsTheCall(t *testing.T) {
	barrier := newTestBarrier(t)
	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}
	require.NoError(t, barrier.Seal())
	d.SetAuditLogger(failingAuditLogger{})

	_, dbusErr := c.SearchItems(map[string]string{})
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
}

func TestCollection_SearchItems_StoreFailure(t *testing.T) {
	store := newErrStore()
	store.listByFolderDirectErr = errStoreUnavailable
	d := newBusDaemon(t, store).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}

	_, dbusErr := c.SearchItems(map[string]string{})
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errStoreUnavailable.Error())
}

func TestCollection_SearchItems_AuditWriteFailureFailsTheCall(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}
	d.SetAuditLogger(failingAuditLogger{})

	_, dbusErr := c.SearchItems(map[string]string{})
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
}

func TestCollection_CreateItem_UnknownSession(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}

	secret := SecretStruct{Session: "/no/such/session", Value: []byte("s3cret")}
	_, _, dbusErr := c.CreateItem(map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("GitHub"),
	}, secret, false)
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), ErrSessionNotFound.Error())
}

func TestCollection_CreateItem_EmptySecret(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}

	secret := testSecret(t, d, "")
	_, _, dbusErr := c.CreateItem(map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("GitHub"),
	}, secret, false)
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), ErrSecretValueEmpty.Error())
}

func TestCollection_CreateItem_ReplaceUpdatesExistingItem(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}

	first := testSecret(t, d, "first-secret")
	_, _, dbusErr := c.CreateItem(map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("GitHub"),
	}, first, false)
	require.Nil(t, dbusErr)

	second := testSecret(t, d, "second-secret")
	_, _, dbusErr = c.CreateItem(map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("GitHub"),
	}, second, true)
	require.Nil(t, dbusErr)

	pw, err := store.Get(xkms.GenerateStaticPasswordID("GitHub", "Work"))
	require.NoError(t, err)
	assert.Equal(t, "second-secret", pw.Password)
}

func TestCollection_CreateItem_NameConflictWithoutReplace(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}

	first := testSecret(t, d, "first-secret")
	_, _, dbusErr := c.CreateItem(map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("GitHub"),
	}, first, false)
	require.Nil(t, dbusErr)

	second := testSecret(t, d, "second-secret")
	_, _, dbusErr = c.CreateItem(map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("GitHub"),
	}, second, false)
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), ErrNameConflict.Error())
}
