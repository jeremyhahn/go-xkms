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

func newTestItem(t *testing.T, d *Daemon, store xkms.StaticPasswordStore, pw *xkms.StaticPassword) *itemObject {
	t.Helper()
	require.NoError(t, store.Add(pw))
	collectionPath, err := d.exportCollection(pw.FolderPath)
	require.NoError(t, err)
	itemPath, err := d.exportItem(collectionPath, pw.ID)
	require.NoError(t, err)
	return &itemObject{daemon: d, path: itemPath, passwordID: pw.ID}
}

func TestItem_GetSecret(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	item := newTestItem(t, d, store, &xkms.StaticPassword{ID: "gh", Name: "GitHub", Password: "s3cret"})

	t.Run("success", func(t *testing.T) {
		_, sessionPath, dbusErr := d.OpenSession(testSender, AlgorithmPlain, dbus.MakeVariant(""))
		require.Nil(t, dbusErr)

		secret, dbusErr := item.GetSecret(sessionPath)
		require.Nil(t, dbusErr)
		assert.Equal(t, []byte("s3cret"), secret.Value)
	})

	t.Run("unknown_session", func(t *testing.T) {
		_, dbusErr := item.GetSecret("/no/such/session")
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrSessionNotFound.Error())
	})
}

func TestItem_SetSecret(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	item := newTestItem(t, d, store, &xkms.StaticPassword{ID: "gh", Name: "GitHub", Password: "old-secret"})

	t.Run("success", func(t *testing.T) {
		secret := testSecret(t, d, "new-secret")
		dbusErr := item.SetSecret(secret)
		require.Nil(t, dbusErr)

		pw, err := store.Get("gh")
		require.NoError(t, err)
		assert.Equal(t, "new-secret", pw.Password)
	})

	t.Run("empty_value_is_refused", func(t *testing.T) {
		secret := testSecret(t, d, "")
		dbusErr := item.SetSecret(secret)
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrSecretValueEmpty.Error())
	})

	t.Run("unknown_session_is_refused", func(t *testing.T) {
		dbusErr := item.SetSecret(SecretStruct{Session: "/no/such/session", Value: []byte("x")})
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrSessionNotFound.Error())
	})

	t.Run("while_sealed_refuses", func(t *testing.T) {
		require.NoError(t, d.barrier.Seal())
		defer func() { require.NoError(t, d.barrier.Unseal(d.ctx, testCredentials(t))) }()

		secret := SecretStruct{Session: "/no/such/session", Value: []byte("x")}
		dbusErr := item.SetSecret(secret)
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrCollectionLocked.Error())
	})
}

func TestItem_SetSecret_StoreFailures(t *testing.T) {
	t.Run("get_fails", func(t *testing.T) {
		store := newErrStore()
		d := newBusDaemon(t, store).Daemon
		item := newTestItem(t, d, store, &xkms.StaticPassword{ID: "gh", Name: "GitHub", Password: "old-secret"})
		store.getErr = errStoreUnavailable

		secret := testSecret(t, d, "new-secret")
		dbusErr := item.SetSecret(secret)
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), errStoreUnavailable.Error())
	})

	t.Run("update_fails", func(t *testing.T) {
		store := newErrStore()
		d := newBusDaemon(t, store).Daemon
		item := newTestItem(t, d, store, &xkms.StaticPassword{ID: "gh", Name: "GitHub", Password: "old-secret"})
		store.updateErr = errStoreUnavailable

		secret := testSecret(t, d, "new-secret")
		dbusErr := item.SetSecret(secret)
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), errStoreUnavailable.Error())
	})
}

func TestItem_SetSecret_AuditWriteFailureFailsTheCall(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	item := newTestItem(t, d, store, &xkms.StaticPassword{ID: "gh", Name: "GitHub", Password: "old-secret"})

	secret := testSecret(t, d, "new-secret")
	d.SetAuditLogger(failingAuditLogger{})

	dbusErr := item.SetSecret(secret)
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
}

func TestItem_Delete(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon

	t.Run("success", func(t *testing.T) {
		item := newTestItem(t, d, store, &xkms.StaticPassword{ID: "gh1", Name: "GitHub1", Password: "s3cret"})
		promptPath, dbusErr := item.Delete()
		require.Nil(t, dbusErr)
		assert.Equal(t, dbus.ObjectPath("/"), promptPath)

		_, err := store.Get("gh1")
		assert.Error(t, err)
	})

	t.Run("read_only_entry_is_refused", func(t *testing.T) {
		item := newTestItem(t, d, store, &xkms.StaticPassword{ID: "gh2", Name: "GitHub2", Password: "s3cret", ReadOnly: true})
		_, dbusErr := item.Delete()
		require.NotNil(t, dbusErr)
	})

	t.Run("while_sealed_refuses", func(t *testing.T) {
		item := newTestItem(t, d, store, &xkms.StaticPassword{ID: "gh3", Name: "GitHub3", Password: "s3cret"})
		require.NoError(t, d.barrier.Seal())
		defer func() { require.NoError(t, d.barrier.Unseal(d.ctx, testCredentials(t))) }()

		_, dbusErr := item.Delete()
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrCollectionLocked.Error())
	})
}

func TestItem_Properties(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	item := newTestItem(t, d, store, &xkms.StaticPassword{
		ID: "gh", Name: "GitHub", Password: "s3cret",
		Attributes: map[string]string{"host": "github.com"},
	})

	t.Run("get_all", func(t *testing.T) {
		props, dbusErr := item.GetAll(ItemInterface)
		require.Nil(t, dbusErr)
		assert.Equal(t, false, props["Locked"].Value())
		attrs, ok := props["Attributes"].Value().(map[string]string)
		require.True(t, ok)
		assert.Equal(t, "github.com", attrs["host"])
	})

	t.Run("get_all_wrong_interface", func(t *testing.T) {
		_, dbusErr := item.GetAll(CollectionInterface)
		require.NotNil(t, dbusErr)
	})

	t.Run("get_single_property", func(t *testing.T) {
		v, dbusErr := item.Get(ItemInterface, "Label")
		require.Nil(t, dbusErr)
		assert.Equal(t, "GitHub", v.Value())
	})

	t.Run("get_wrong_interface", func(t *testing.T) {
		_, dbusErr := item.Get(CollectionInterface, "Label")
		require.NotNil(t, dbusErr)
	})

	t.Run("get_unknown_property", func(t *testing.T) {
		_, dbusErr := item.Get(ItemInterface, "Bogus")
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrPropertyNotFound.Error())
	})

	t.Run("set_label", func(t *testing.T) {
		dbusErr := item.Set(ItemInterface, "Label", dbus.MakeVariant("renamed"))
		require.Nil(t, dbusErr)

		pw, err := store.Get("gh")
		require.NoError(t, err)
		assert.Equal(t, "renamed", pw.DisplayTitle())
	})

	t.Run("set_attributes", func(t *testing.T) {
		dbusErr := item.Set(ItemInterface, "Attributes", dbus.MakeVariant(map[string]string{"host": "example.com"}))
		require.Nil(t, dbusErr)

		pw, err := store.Get("gh")
		require.NoError(t, err)
		assert.Equal(t, "example.com", pw.Attributes["host"])
	})

	t.Run("set_label_wrong_type", func(t *testing.T) {
		dbusErr := item.Set(ItemInterface, "Label", dbus.MakeVariant(42))
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrPropertyInvalidValue.Error())
	})

	t.Run("set_attributes_wrong_type", func(t *testing.T) {
		dbusErr := item.Set(ItemInterface, "Attributes", dbus.MakeVariant("not-a-map"))
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrPropertyInvalidValue.Error())
	})

	t.Run("set_wrong_interface", func(t *testing.T) {
		dbusErr := item.Set(CollectionInterface, "Label", dbus.MakeVariant("x"))
		require.NotNil(t, dbusErr)
	})

	t.Run("set_unknown_property", func(t *testing.T) {
		dbusErr := item.Set(ItemInterface, "Bogus", dbus.MakeVariant("x"))
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrPropertyNotFound.Error())
	})

	t.Run("set_locked_is_read_only", func(t *testing.T) {
		dbusErr := item.Set(ItemInterface, "Locked", dbus.MakeVariant(true))
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrPropertyReadOnly.Error())
	})

	t.Run("set_while_sealed_refuses", func(t *testing.T) {
		require.NoError(t, d.barrier.Seal())
		defer func() { require.NoError(t, d.barrier.Unseal(d.ctx, testCredentials(t))) }()

		dbusErr := item.Set(ItemInterface, "Label", dbus.MakeVariant("x"))
		require.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), ErrCollectionLocked.Error())
	})

	t.Run("get_all_while_sealed_never_returns_attributes", func(t *testing.T) {
		require.NoError(t, d.barrier.Seal())
		defer func() { require.NoError(t, d.barrier.Unseal(d.ctx, testCredentials(t))) }()

		props, dbusErr := item.GetAll(ItemInterface)
		require.Nil(t, dbusErr)
		assert.Equal(t, true, props["Locked"].Value())
		attrs, ok := props["Attributes"].Value().(map[string]string)
		require.True(t, ok)
		assert.Empty(t, attrs)
	})
}
