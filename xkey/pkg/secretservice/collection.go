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
	"log/slog"

	"github.com/godbus/dbus/v5"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// collectionObject implements org.freedesktop.Secret.Collection and
// org.freedesktop.DBus.Properties for a single collection, which corresponds
// 1:1 to a go-xkms static-password folder (folder == "" is the default/login
// collection). It is stateless beyond the folder it addresses: every method
// reads and writes through daemon.store, so the object is always consistent
// with the current barrier state and never caches a secret.
type collectionObject struct {
	daemon *Daemon
	path   dbus.ObjectPath
	folder string
}

// exportCollection exports the collection object for folder on the bus and
// returns its object path. Safe to call more than once for the same folder
// (e.g. on every Start, and again from CreateCollection): godbus's Export
// replaces the handler at (path, interface) rather than erroring on the
// second registration.
func (d *Daemon) exportCollection(folder string) (dbus.ObjectPath, error) {
	path := d.mapper.CollectionPathFromFolder(folder)
	if d.conn == nil {
		return path, nil
	}
	obj := &collectionObject{daemon: d, path: path, folder: folder}
	if err := d.conn.Export(obj, path, CollectionInterface); err != nil {
		return "", &WrappedError{Msg: "failed to export Collection", Err: err}
	}
	if err := d.conn.Export(obj, path, DBusPropertiesInterface); err != nil {
		return "", &WrappedError{Msg: "failed to export Collection properties", Err: err}
	}
	return path, nil
}

// unexportCollection removes the collection object (and its item children)
// from the bus. Item paths are supplied by the caller, which already has
// them from the folder listing it used to build the delete set.
func (d *Daemon) unexportCollection(path dbus.ObjectPath, itemPaths []dbus.ObjectPath) {
	for _, itemPath := range itemPaths {
		d.unexportItem(itemPath)
	}
	if d.conn == nil {
		return
	}
	_ = d.conn.Export(nil, path, CollectionInterface)
	_ = d.conn.Export(nil, path, DBusPropertiesInterface)
}

// exportExistingCollections exports the default collection plus one object
// per persisted folder, and one item object per stored password within each.
// Called from Start once the barrier is unsealed (either already unsealed
// when the daemon starts, or after a Prompt-driven Unlock): while sealed,
// staticpw.Store cannot enumerate anything (folders and passwords are
// indistinguishable encrypted blobs to it), so there is nothing to export
// yet beyond the always-present default collection Start already exports
// unconditionally.
func (d *Daemon) exportExistingCollections() error {
	folders, err := d.store.ListFolders()
	if err != nil {
		return &WrappedError{Msg: "failed to list folders", Err: err}
	}
	for _, folder := range folders {
		if _, err := d.exportCollection(folder); err != nil {
			return err
		}
	}

	passwords, err := d.store.List()
	if err != nil {
		return &WrappedError{Msg: "failed to list passwords", Err: err}
	}
	for _, pw := range passwords {
		collectionPath := d.mapper.CollectionPathFromFolder(pw.FolderPath)
		if _, err := d.exportItem(collectionPath, pw.ID); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes the collection: every item directly in its folder, the
// folder marker itself (RemoveFolder is a no-op for the default folder,
// which has none), and the exported D-Bus objects. It never returns a
// prompt: deleting an already-unlocked collection needs no further
// confirmation from this daemon's client.
func (c *collectionObject) Delete() (dbus.ObjectPath, *dbus.Error) {
	d := c.daemon
	if d.barrier.IsSealed() {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceCollectionDeleted, false, ErrCollectionLocked, map[string]any{"folder": c.folder}); auditErr != nil {
			return "/", dbus.MakeFailedError(auditErr)
		}
		return "/", dbusIsLockedError(ErrCollectionLocked)
	}

	passwords, err := d.store.ListByFolderDirect(c.folder)
	if err != nil {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceCollectionDeleted, false, err, map[string]any{"folder": c.folder}); auditErr != nil {
			return "/", dbus.MakeFailedError(auditErr)
		}
		return "/", dbus.MakeFailedError(err)
	}

	itemPaths := make([]dbus.ObjectPath, 0, len(passwords))
	for _, pw := range passwords {
		if delErr := d.store.Delete(pw.ID); delErr != nil {
			d.logger.Warn("collection delete: failed to delete item",
				slog.String("folder", c.folder), slog.String("id", pw.ID), slog.String("error", delErr.Error()))
			continue
		}
		itemPaths = append(itemPaths, d.mapper.ItemPathFromPassword(c.path, pw.ID))
	}

	if c.folder != "" {
		if err := d.store.RemoveFolder(c.folder); err != nil {
			if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceCollectionDeleted, false, err, map[string]any{"folder": c.folder}); auditErr != nil {
				return "/", dbus.MakeFailedError(auditErr)
			}
			return "/", dbus.MakeFailedError(err)
		}
	}

	d.unexportCollection(c.path, itemPaths)

	if emitErr := d.conn.Emit(ServicePath, ServiceInterface+".CollectionDeleted", c.path); emitErr != nil {
		d.logger.Warn("failed to emit CollectionDeleted signal", slog.String("error", emitErr.Error()))
	}

	if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceCollectionDeleted, true, nil, map[string]any{"folder": c.folder, "item_count": len(itemPaths)}); auditErr != nil {
		return "/", dbus.MakeFailedError(auditErr)
	}
	return "/", nil
}

// SearchItems searches only within this collection's folder.
func (c *collectionObject) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	d := c.daemon
	if d.barrier.IsSealed() {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSearch, false, ErrCollectionLocked, map[string]any{"folder": c.folder}); auditErr != nil {
			return nil, dbus.MakeFailedError(auditErr)
		}
		return nil, dbusIsLockedError(ErrCollectionLocked)
	}

	passwords, err := d.store.ListByFolderDirect(c.folder)
	if err != nil {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSearch, false, err, map[string]any{"folder": c.folder}); auditErr != nil {
			return nil, dbus.MakeFailedError(auditErr)
		}
		return nil, dbus.MakeFailedError(err)
	}

	search := ItemAttributes(attributes)
	var results []dbus.ObjectPath
	for _, pw := range passwords {
		if MatchAttributes(ItemAttributesFromPassword(pw), search) {
			results = append(results, d.mapper.ItemPathFromPassword(c.path, pw.ID))
		}
	}

	if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSearch, true, nil, map[string]any{"folder": c.folder, "result_count": len(results)}); auditErr != nil {
		return nil, dbus.MakeFailedError(auditErr)
	}
	return results, nil
}

// CreateItem creates a new item in this collection from a session-encrypted
// (or plain) secret and D-Bus item properties, matching the argument order
// the freedesktop Secret Service API specifies:
// CreateItem(properties, secret, replace) -> (item, prompt).
func (c *collectionObject) CreateItem(properties map[string]dbus.Variant, secret SecretStruct, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	d := c.daemon
	if d.barrier.IsSealed() {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceItemCreated, false, ErrCollectionLocked, map[string]any{"folder": c.folder}); auditErr != nil {
			return "/", "/", dbus.MakeFailedError(auditErr)
		}
		return "/", "/", dbusIsLockedError(ErrCollectionLocked)
	}

	label, attrs := parseItemProperties(properties)
	if label == "" {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceItemCreated, false, ErrLabelRequired, map[string]any{"folder": c.folder}); auditErr != nil {
			return "/", "/", dbus.MakeFailedError(auditErr)
		}
		return "/", "/", dbus.MakeFailedError(ErrLabelRequired)
	}

	value, decErr := d.decryptSecret(secret)
	if decErr != nil {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceItemCreated, false, decErr, map[string]any{"folder": c.folder}); auditErr != nil {
			return "/", "/", dbus.MakeFailedError(auditErr)
		}
		return "/", "/", mapSecretError(decErr)
	}
	if len(value) == 0 {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceItemCreated, false, ErrSecretValueEmpty, map[string]any{"folder": c.folder}); auditErr != nil {
			return "/", "/", dbus.MakeFailedError(auditErr)
		}
		return "/", "/", dbus.MakeFailedError(ErrSecretValueEmpty)
	}

	id := xkms.GenerateStaticPasswordID(label, c.folder)
	existing, getErr := d.store.Get(id)
	exists := getErr == nil && existing != nil

	pw := &xkms.StaticPassword{
		ID:         id,
		Name:       label,
		FolderPath: c.folder,
		Password:   string(value),
		Attributes: attrs,
	}
	if v, ok := attrs["username"]; ok {
		pw.Username = v
	}
	if v, ok := attrs["url"]; ok {
		pw.URL = v
	}

	var storeErr error
	switch {
	case exists && replace:
		storeErr = d.store.Update(pw)
	case exists && !replace:
		storeErr = ErrNameConflict
	default:
		storeErr = d.store.Add(pw)
	}
	if storeErr != nil {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceItemCreated, false, storeErr, map[string]any{"folder": c.folder, "label": label}); auditErr != nil {
			return "/", "/", dbus.MakeFailedError(auditErr)
		}
		return "/", "/", dbus.MakeFailedError(storeErr)
	}

	itemPath, exportErr := d.exportItem(c.path, pw.ID)
	if exportErr != nil {
		return "/", "/", dbus.MakeFailedError(exportErr)
	}

	if emitErr := d.conn.Emit(ServicePath, ServiceInterface+".CollectionChanged", c.path); emitErr != nil {
		d.logger.Warn("failed to emit CollectionChanged signal", slog.String("error", emitErr.Error()))
	}

	if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceItemCreated, true, nil, map[string]any{"folder": c.folder, "label": label, "replaced": exists}); auditErr != nil {
		return "/", "/", dbus.MakeFailedError(auditErr)
	}
	return itemPath, "/", nil
}

// parseItemProperties extracts the item Label and Attributes from the
// property bag CreateItem receives, tolerating a missing or mistyped
// Attributes entry (an empty attribute set) rather than failing the call.
func parseItemProperties(properties map[string]dbus.Variant) (label string, attrs map[string]string) {
	if labelVar, ok := properties["org.freedesktop.Secret.Item.Label"]; ok {
		if l, ok := labelVar.Value().(string); ok {
			label = l
		}
	}
	if attrsVar, ok := properties["org.freedesktop.Secret.Item.Attributes"]; ok {
		if a, ok := attrsVar.Value().(map[string]string); ok {
			attrs = a
		}
	}
	return label, attrs
}

// --- org.freedesktop.DBus.Properties ---

// Get implements org.freedesktop.DBus.Properties.Get for a collection.
func (c *collectionObject) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	if iface != CollectionInterface {
		return dbus.Variant{}, dbus.MakeFailedError(ErrInterfaceNotFound)
	}
	all, dbusErr := c.GetAll(iface)
	if dbusErr != nil {
		return dbus.Variant{}, dbusErr
	}
	v, ok := all[property]
	if !ok {
		return dbus.Variant{}, dbus.MakeFailedError(ErrPropertyNotFound)
	}
	return v, nil
}

// GetAll implements org.freedesktop.DBus.Properties.GetAll for a collection.
func (c *collectionObject) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	if iface != CollectionInterface {
		return nil, dbus.MakeFailedError(ErrInterfaceNotFound)
	}
	d := c.daemon
	locked := d.barrier.IsSealed()

	props := map[string]dbus.Variant{
		"Label":  dbus.MakeVariant(c.label()),
		"Locked": dbus.MakeVariant(locked),
	}

	if locked {
		// The store cannot be read while sealed; Items/Created/Modified
		// would require decrypting entries this call must not touch.
		props["Items"] = dbus.MakeVariant([]dbus.ObjectPath{})
		props["Created"] = dbus.MakeVariant(uint64(0))
		props["Modified"] = dbus.MakeVariant(uint64(0))
		return props, nil
	}

	passwords, err := d.store.ListByFolderDirect(c.folder)
	if err != nil {
		return nil, dbus.MakeFailedError(err)
	}

	items := make([]dbus.ObjectPath, 0, len(passwords))
	var created, modified uint64
	for i, pw := range passwords {
		items = append(items, d.mapper.ItemPathFromPassword(c.path, pw.ID))
		pwCreated := uint64(pw.CreatedAt.Unix())
		pwModified := uint64(pw.UpdatedAt.Unix())
		if i == 0 || pwCreated < created {
			created = pwCreated
		}
		if pwModified > modified {
			modified = pwModified
		}
	}
	props["Items"] = dbus.MakeVariant(items)
	props["Created"] = dbus.MakeVariant(created)
	props["Modified"] = dbus.MakeVariant(modified)
	return props, nil
}

// Set implements org.freedesktop.DBus.Properties.Set for a collection.
// Label is intentionally read-only from this side: renaming a collection
// means renaming its underlying folder, which regenerates the ID (and
// therefore the D-Bus object path) of every item inside it -- neither
// secret-tool nor git-credential-libsecret, this daemon's two verification
// targets, ever calls Collection.Set, so the folder-rename cascade is left
// unimplemented rather than shipped half-built; see docs/secret-service/engineering.md.
func (c *collectionObject) Set(iface, property string, value dbus.Variant) *dbus.Error {
	if iface != CollectionInterface {
		return dbus.MakeFailedError(ErrInterfaceNotFound)
	}
	switch property {
	case "Label", "Locked", "Items", "Created", "Modified":
		return dbus.MakeFailedError(ErrPropertyReadOnly)
	default:
		return dbus.MakeFailedError(ErrPropertyNotFound)
	}
}

// label returns the display label for this collection: the default/login
// alias name for the root folder, otherwise the folder path itself.
func (c *collectionObject) label() string {
	if c.folder == "" {
		return DefaultCollection
	}
	return c.folder
}
