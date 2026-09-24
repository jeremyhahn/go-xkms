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
	"github.com/godbus/dbus/v5"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// itemObject implements org.freedesktop.Secret.Item and
// org.freedesktop.DBus.Properties for a single stored password entry.
type itemObject struct {
	daemon     *Daemon
	path       dbus.ObjectPath
	passwordID string
}

// exportItem exports the item object for passwordID under collectionPath
// and returns its object path. Idempotent, like exportCollection.
func (d *Daemon) exportItem(collectionPath dbus.ObjectPath, passwordID string) (dbus.ObjectPath, error) {
	path := d.mapper.ItemPathFromPassword(collectionPath, passwordID)
	if d.conn == nil {
		return path, nil
	}
	obj := &itemObject{daemon: d, path: path, passwordID: passwordID}
	if err := d.conn.Export(obj, path, ItemInterface); err != nil {
		return "", &WrappedError{Msg: "failed to export Item", Err: err}
	}
	if err := d.conn.Export(obj, path, DBusPropertiesInterface); err != nil {
		return "", &WrappedError{Msg: "failed to export Item properties", Err: err}
	}
	return path, nil
}

// unexportItem removes the item object from the bus.
func (d *Daemon) unexportItem(path dbus.ObjectPath) {
	if d.conn == nil {
		return
	}
	_ = d.conn.Export(nil, path, ItemInterface)
	_ = d.conn.Export(nil, path, DBusPropertiesInterface)
}

// Delete removes the underlying password entry. Read-only entries (e.g.
// TPM-policy-generated) are refused by the store itself
// (xkms.ErrStaticPasswordReadOnly) and surfaced as-is.
func (i *itemObject) Delete() (dbus.ObjectPath, *dbus.Error) {
	d := i.daemon
	if d.barrier.IsSealed() {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceItemDeleted, false, ErrCollectionLocked, map[string]any{"id": i.passwordID}); auditErr != nil {
			return "/", dbus.MakeFailedError(auditErr)
		}
		return "/", dbusIsLockedError(ErrCollectionLocked)
	}

	if err := d.store.Delete(i.passwordID); err != nil {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceItemDeleted, false, err, map[string]any{"id": i.passwordID}); auditErr != nil {
			return "/", dbus.MakeFailedError(auditErr)
		}
		return "/", dbus.MakeFailedError(err)
	}

	d.unexportItem(i.path)

	if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceItemDeleted, true, nil, map[string]any{"id": i.passwordID}); auditErr != nil {
		return "/", dbus.MakeFailedError(auditErr)
	}
	return "/", nil
}

// GetSecret retrieves this item's secret over an established session,
// delegating to Daemon.GetSecrets (which already audits the access) rather
// than duplicating its crypto/lock handling.
func (i *itemObject) GetSecret(session dbus.ObjectPath) (SecretStruct, *dbus.Error) {
	secrets, dbusErr := i.daemon.GetSecrets([]dbus.ObjectPath{i.path}, session)
	if dbusErr != nil {
		return SecretStruct{}, dbusErr
	}
	secret, ok := secrets[i.path]
	if !ok {
		return SecretStruct{}, dbusNoSuchObjectError(ErrItemNotFound)
	}
	return secret, nil
}

// SetSecret updates this item's stored password from a session-encrypted
// (or plain) secret.
func (i *itemObject) SetSecret(secret SecretStruct) *dbus.Error {
	d := i.daemon
	if d.barrier.IsSealed() {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSecretAccessed, false, ErrCollectionLocked, map[string]any{"id": i.passwordID, "op": "set_secret"}); auditErr != nil {
			return dbus.MakeFailedError(auditErr)
		}
		return dbusIsLockedError(ErrCollectionLocked)
	}

	value, decErr := d.decryptSecret(secret)
	if decErr != nil {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSecretAccessed, false, decErr, map[string]any{"id": i.passwordID, "op": "set_secret"}); auditErr != nil {
			return dbus.MakeFailedError(auditErr)
		}
		return mapSecretError(decErr)
	}
	if len(value) == 0 {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSecretAccessed, false, ErrSecretValueEmpty, map[string]any{"id": i.passwordID, "op": "set_secret"}); auditErr != nil {
			return dbus.MakeFailedError(auditErr)
		}
		return dbus.MakeFailedError(ErrSecretValueEmpty)
	}

	pw, err := d.store.Get(i.passwordID)
	if err != nil {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSecretAccessed, false, err, map[string]any{"id": i.passwordID, "op": "set_secret"}); auditErr != nil {
			return dbus.MakeFailedError(auditErr)
		}
		return dbusNoSuchObjectError(err)
	}

	pw.Password = string(value)
	if err := d.store.Update(pw); err != nil {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSecretAccessed, false, err, map[string]any{"id": i.passwordID, "op": "set_secret"}); auditErr != nil {
			return dbus.MakeFailedError(auditErr)
		}
		return dbus.MakeFailedError(err)
	}

	if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSecretAccessed, true, nil, map[string]any{"id": i.passwordID, "op": "set_secret"}); auditErr != nil {
		return dbus.MakeFailedError(auditErr)
	}
	return nil
}

// --- org.freedesktop.DBus.Properties ---

// Get implements org.freedesktop.DBus.Properties.Get for an item.
func (i *itemObject) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	if iface != ItemInterface {
		return dbus.Variant{}, dbus.MakeFailedError(ErrInterfaceNotFound)
	}
	all, dbusErr := i.GetAll(iface)
	if dbusErr != nil {
		return dbus.Variant{}, dbusErr
	}
	v, ok := all[property]
	if !ok {
		return dbus.Variant{}, dbus.MakeFailedError(ErrPropertyNotFound)
	}
	return v, nil
}

// GetAll implements org.freedesktop.DBus.Properties.GetAll for an item.
func (i *itemObject) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	if iface != ItemInterface {
		return nil, dbus.MakeFailedError(ErrInterfaceNotFound)
	}
	d := i.daemon
	locked := d.barrier.IsSealed()

	if locked {
		return map[string]dbus.Variant{
			"Locked":     dbus.MakeVariant(true),
			"Attributes": dbus.MakeVariant(map[string]string{}),
			"Label":      dbus.MakeVariant(""),
			"Created":    dbus.MakeVariant(uint64(0)),
			"Modified":   dbus.MakeVariant(uint64(0)),
		}, nil
	}

	pw, err := d.store.Get(i.passwordID)
	if err != nil {
		return nil, dbusNoSuchObjectError(err)
	}

	return map[string]dbus.Variant{
		"Locked":     dbus.MakeVariant(false),
		"Attributes": dbus.MakeVariant(map[string]string(ItemAttributesFromPassword(pw))),
		"Label":      dbus.MakeVariant(pw.DisplayTitle()),
		"Created":    dbus.MakeVariant(uint64(pw.CreatedAt.Unix())),
		"Modified":   dbus.MakeVariant(uint64(pw.UpdatedAt.Unix())),
	}, nil
}

// Set implements org.freedesktop.DBus.Properties.Set for an item. Label and
// Attributes are writable: neither changes the entry's Name/FolderPath, so
// neither regenerates its ID or D-Bus object path.
func (i *itemObject) Set(iface, property string, value dbus.Variant) *dbus.Error {
	if iface != ItemInterface {
		return dbus.MakeFailedError(ErrInterfaceNotFound)
	}
	d := i.daemon
	if d.barrier.IsSealed() {
		return dbusIsLockedError(ErrCollectionLocked)
	}

	pw, err := d.store.Get(i.passwordID)
	if err != nil {
		return dbusNoSuchObjectError(err)
	}

	switch property {
	case "Label":
		label, ok := value.Value().(string)
		if !ok {
			return dbus.MakeFailedError(ErrPropertyInvalidValue)
		}
		pw.Title = label
	case "Attributes":
		attrs, ok := value.Value().(map[string]string)
		if !ok {
			return dbus.MakeFailedError(ErrPropertyInvalidValue)
		}
		pw.Attributes = attrs
	case "Locked", "Created", "Modified":
		return dbus.MakeFailedError(ErrPropertyReadOnly)
	default:
		return dbus.MakeFailedError(ErrPropertyNotFound)
	}

	if err := d.store.Update(pw); err != nil {
		return dbus.MakeFailedError(err)
	}
	return nil
}
