package secretservice

// Every Secret Service call is audited, refusals included. When the refusal
// itself cannot be audited the call must report the audit failure, change
// nothing, and leave the barrier sealed.

import (
	"context"
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

var errStoreDown = errors.New("store: unavailable")

func labelProps(label string) map[string]dbus.Variant {
	return map[string]dbus.Variant{"org.freedesktop.Secret.Item.Label": dbus.MakeVariant(label)}
}

func requireAuditFailure(t *testing.T, dbusErr *dbus.Error) {
	t.Helper()
	require.NotNil(t, dbusErr, "a refusal that could not be audited must not succeed")
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
}

func TestSealedRefusals_AuditWriteFailureFailsTheCall(t *testing.T) {
	tests := []struct {
		name string
		call func(c *collectionObject, item *itemObject, secret SecretStruct) *dbus.Error
	}{
		{name: "create collection", call: func(c *collectionObject, _ *itemObject, _ SecretStruct) *dbus.Error {
			_, _, err := c.daemon.CreateCollection(map[string]dbus.Variant{}, "")
			return err
		}},
		{name: "get secrets", call: func(c *collectionObject, item *itemObject, secret SecretStruct) *dbus.Error {
			_, err := c.daemon.GetSecrets([]dbus.ObjectPath{item.path}, secret.Session)
			return err
		}},
		{name: "search collection", call: func(c *collectionObject, _ *itemObject, _ SecretStruct) *dbus.Error {
			_, err := c.SearchItems(map[string]string{})
			return err
		}},
		{name: "delete collection", call: func(c *collectionObject, _ *itemObject, _ SecretStruct) *dbus.Error {
			_, err := c.Delete()
			return err
		}},
		{name: "create item", call: func(c *collectionObject, _ *itemObject, secret SecretStruct) *dbus.Error {
			_, _, err := c.CreateItem(labelProps("GitLab"), secret, false)
			return err
		}},
		{name: "delete item", call: func(_ *collectionObject, item *itemObject, _ SecretStruct) *dbus.Error {
			_, err := item.Delete()
			return err
		}},
		{name: "set secret", call: func(_ *collectionObject, item *itemObject, secret SecretStruct) *dbus.Error {
			return item.SetSecret(secret)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMemoryStore()
			barrier := newTestBarrier(t)
			d := newBusDaemonWithBarrier(t, store, barrier).Daemon
			item := newTestItem(t, d, store, &xkms.StaticPassword{ID: "gh", Name: "GitHub", Password: "s3cret"})
			c := &collectionObject{daemon: d, path: d.mapper.CollectionPathFromFolder(""), folder: ""}
			secret := testSecret(t, d, "n3w")
			require.NoError(t, barrier.Seal())
			d.SetAuditLogger(failingAuditLogger{})

			requireAuditFailure(t, tt.call(c, item, secret))

			assert.True(t, barrier.IsSealed())
			pw, err := store.Get("gh")
			require.NoError(t, err, "a refused call must not delete the item")
			assert.Equal(t, "s3cret", pw.Password, "a refused call must not change the secret")
			assert.Len(t, store.passwords, 1, "a refused call must not add items")
		})
	}
}

func TestRefusals_AuditWriteFailureFailsTheCall(t *testing.T) {
	tests := []struct {
		name  string
		setup func(s *errStore)
		call  func(t *testing.T, d *Daemon, c *collectionObject, s *errStore) *dbus.Error
	}{
		{name: "create item without a label", call: func(t *testing.T, d *Daemon, c *collectionObject, _ *errStore) *dbus.Error {
			_, _, err := c.CreateItem(map[string]dbus.Variant{}, testSecret(t, d, "v"), false)
			return err
		}},
		{name: "create item with an unknown session", call: func(_ *testing.T, _ *Daemon, c *collectionObject, _ *errStore) *dbus.Error {
			_, _, err := c.CreateItem(labelProps("GitLab"), SecretStruct{Session: "/no/such/session", Value: []byte("v")}, false)
			return err
		}},
		{name: "create item with an empty secret", call: func(t *testing.T, d *Daemon, c *collectionObject, _ *errStore) *dbus.Error {
			_, _, err := c.CreateItem(labelProps("GitLab"), testSecret(t, d, ""), false)
			return err
		}},
		{name: "create item that already exists", call: func(t *testing.T, d *Daemon, c *collectionObject, s *errStore) *dbus.Error {
			require.NoError(t, s.Add(&xkms.StaticPassword{ID: xkms.GenerateStaticPasswordID("GitLab", ""), Name: "GitLab", Password: "old"}))
			_, _, err := c.CreateItem(labelProps("GitLab"), testSecret(t, d, "v"), false)
			return err
		}},
		{name: "search a collection the store cannot list", setup: func(s *errStore) { s.listByFolderDirectErr = errStoreDown },
			call: func(_ *testing.T, _ *Daemon, c *collectionObject, _ *errStore) *dbus.Error {
				_, err := c.SearchItems(map[string]string{})
				return err
			}},
		{name: "delete a collection the store cannot list", setup: func(s *errStore) { s.listByFolderDirectErr = errStoreDown },
			call: func(_ *testing.T, _ *Daemon, c *collectionObject, _ *errStore) *dbus.Error {
				_, err := c.Delete()
				return err
			}},
		{name: "create a collection the store cannot create", setup: func(s *errStore) { s.createFolderErr = errStoreDown },
			call: func(_ *testing.T, d *Daemon, _ *collectionObject, _ *errStore) *dbus.Error {
				_, _, err := d.CreateCollection(map[string]dbus.Variant{}, "work")
				return err
			}},
		{name: "delete a read-only item", call: func(t *testing.T, d *Daemon, _ *collectionObject, s *errStore) *dbus.Error {
			item := newTestItem(t, d, s, &xkms.StaticPassword{ID: "ro", Name: "Pinned", Password: "p", ReadOnly: true})
			_, err := item.Delete()
			return err
		}},
		{name: "set an empty secret", call: func(t *testing.T, d *Daemon, _ *collectionObject, s *errStore) *dbus.Error {
			item := newTestItem(t, d, s, &xkms.StaticPassword{ID: "gh", Name: "GitHub", Password: "p"})
			return item.SetSecret(testSecret(t, d, ""))
		}},
		{name: "set a secret with an unknown session", call: func(t *testing.T, d *Daemon, _ *collectionObject, s *errStore) *dbus.Error {
			item := newTestItem(t, d, s, &xkms.StaticPassword{ID: "gh", Name: "GitHub", Password: "p"})
			return item.SetSecret(SecretStruct{Session: "/no/such/session", Value: []byte("v")})
		}},
		{name: "set the secret of a missing item", call: func(t *testing.T, d *Daemon, c *collectionObject, _ *errStore) *dbus.Error {
			item := &itemObject{daemon: d, path: d.mapper.ItemPathFromPassword(c.path, "gone"), passwordID: "gone"}
			return item.SetSecret(testSecret(t, d, "v"))
		}},
		{name: "set a secret the store cannot update", setup: func(s *errStore) { s.updateErr = errStoreDown },
			call: func(t *testing.T, d *Daemon, _ *collectionObject, s *errStore) *dbus.Error {
				item := newTestItem(t, d, s, &xkms.StaticPassword{ID: "gh", Name: "GitHub", Password: "p"})
				return item.SetSecret(testSecret(t, d, "v"))
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newErrStore()
			d := newBusDaemon(t, store).Daemon
			c := &collectionObject{daemon: d, path: d.mapper.CollectionPathFromFolder(""), folder: ""}
			if tt.setup != nil {
				tt.setup(store)
			}
			d.SetAuditLogger(failExceptSessionAudit{})

			requireAuditFailure(t, tt.call(t, d, c, store))
		})
	}
}

// failExceptSessionAudit fails every write except OpenSession's, so a table
// case can open the session its call needs (testSecret) under a down sink.
type failExceptSessionAudit struct {
	audit.Logger
}

func (failExceptSessionAudit) Log(e audit.Entry) error {
	if e.Operation == audit.OpSecretServiceSessionOpened {
		return nil
	}
	return errAuditSinkDown
}

func TestCollection_CreateItem_MapsUsernameAndURLAttributes(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	c := &collectionObject{daemon: d, path: d.mapper.CollectionPathFromFolder(""), folder: ""}

	props := labelProps("GitHub")
	props["org.freedesktop.Secret.Item.Attributes"] = dbus.MakeVariant(map[string]string{
		"username": "alice",
		"url":      "https://github.com",
		"service":  "git",
	})
	_, _, dbusErr := c.CreateItem(props, testSecret(t, d, "s3cret"), false)
	require.Nil(t, dbusErr)

	pw, err := store.Get("GitHub")
	require.NoError(t, err)
	assert.Equal(t, "alice", pw.Username)
	assert.Equal(t, "https://github.com", pw.URL)
	assert.Equal(t, "git", pw.Attributes["service"], "other attributes are kept as-is")
}

func TestCollection_Delete_KeepsReadOnlyItems(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	newTestItem(t, d, store, &xkms.StaticPassword{ID: "gh", Name: "GitHub", Password: "p"})
	newTestItem(t, d, store, &xkms.StaticPassword{ID: "ro", Name: "Pinned", Password: "p", ReadOnly: true})
	c := &collectionObject{daemon: d, path: d.mapper.CollectionPathFromFolder(""), folder: ""}

	_, dbusErr := c.Delete()
	require.Nil(t, dbusErr)

	_, err := store.Get("gh")
	assert.ErrorIs(t, err, xkms.ErrStaticPasswordNotFound)
	_, err = store.Get("ro")
	assert.NoError(t, err, "a read-only item must survive its collection being deleted")
}

// unlockPrompt seals the barrier and returns the prompt an Unlock call creates.
func unlockPrompt(t *testing.T, d *Daemon, barrier *xkms.Barrier) *promptObject {
	t.Helper()
	require.NoError(t, barrier.Seal())
	_, promptPath, dbusErr := d.Unlock([]dbus.ObjectPath{d.mapper.CollectionPathFromFolder("")})
	require.Nil(t, dbusErr)
	return &promptObject{daemon: d, path: promptPath}
}

func TestPrompt_UnlockFuncErrorDismisses(t *testing.T) {
	barrier := newTestBarrier(t)
	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	rec := &recordingAudit{}
	d.SetAuditLogger(rec)
	errNoPIN := errors.New("pin entry cancelled")
	d.SetUnlockFunc(func(context.Context) (xkms.SealCredentials, error) {
		return xkms.SealCredentials{}, errNoPIN
	})
	p := unlockPrompt(t, d, barrier)

	require.Nil(t, p.Prompt(""))

	assert.True(t, barrier.IsSealed())
	entries := rec.recorded()
	require.NotEmpty(t, entries)
	last := entries[len(entries)-1]
	assert.Equal(t, audit.OpSecretServiceUnlock, last.Operation)
	assert.False(t, last.Success)
	assert.Equal(t, errNoPIN.Error(), last.Error)
	assert.NotNil(t, p.Prompt(""), "a dismissed prompt cannot be prompted again")
}

func TestPrompt_FailedUnlock_AuditWriteFailureStillDismisses(t *testing.T) {
	wrongCreds := func(t *testing.T) func(context.Context) (xkms.SealCredentials, error) {
		return func(context.Context) (xkms.SealCredentials, error) {
			return xkms.CredentialsFor(t.Context(), []byte("totally-wrong-password"))
		}
	}
	tests := []struct {
		name     string
		unlockFn func(t *testing.T) func(context.Context) (xkms.SealCredentials, error)
		resolve  func(p *promptObject) *dbus.Error
	}{
		{name: "no unlock function", resolve: func(p *promptObject) *dbus.Error { return p.Prompt("") }},
		{name: "unlock function fails", unlockFn: func(*testing.T) func(context.Context) (xkms.SealCredentials, error) {
			return func(context.Context) (xkms.SealCredentials, error) { return xkms.SealCredentials{}, errStoreDown }
		}, resolve: func(p *promptObject) *dbus.Error { return p.Prompt("") }},
		{name: "wrong credentials", unlockFn: wrongCreds, resolve: func(p *promptObject) *dbus.Error { return p.Prompt("") }},
		{name: "dismissed", unlockFn: wrongCreds, resolve: func(p *promptObject) *dbus.Error { return p.Dismiss() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			barrier := newTestBarrier(t)
			d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
			if tt.unlockFn != nil {
				d.SetUnlockFunc(tt.unlockFn(t))
			}
			p := unlockPrompt(t, d, barrier)
			d.SetAuditLogger(failingAuditLogger{})

			requireAuditFailure(t, tt.resolve(p))

			assert.True(t, barrier.IsSealed())
			d.promptsMu.Lock()
			_, pending := d.prompts[p.path]
			d.promptsMu.Unlock()
			assert.False(t, pending, "the prompt completes even when its outcome cannot be audited")
		})
	}
}
