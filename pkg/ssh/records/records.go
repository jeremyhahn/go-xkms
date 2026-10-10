// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

// Package records persists the scoped SSH records -- keys, known_hosts pins
// and authorized_keys entries -- through go-qrdb DAOs in the DatabaseName
// database. It is the one owner-aware record table the keys, known_hosts and
// authorized stores share.
//
// Every record is addressed by (scope, owner, name) inside a tenant
// partition. Its natural key is the partition root followed by the record
// path the SSH scope layout builds:
//
//	{tenant}/ssh/shared/<kind>/<name>             scope=tenant
//	{tenant}/ssh/users/<owner>/<kind>/<name>      scope=user
//	{tenant}/ssh/services/<owner>/<kind>/<name>   scope=service
//
// A tenant-scoped path carries no owner, so the record's Owner is
// authoritative: a record held by another owner answers as missing and is
// never overwritten or deleted.
package records

import (
	"context"
	"sort"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	pkgscope "github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// DatabaseName is the go-qrdb database every SSH record lives in. A
// composition root opens it on the datastore before building the stores.
const DatabaseName = "ssh"

// maxAttempts bounds the read-compare-write retries of one Put or Delete
// racing concurrent writers of the same record.
const maxAttempts = 16

// Entity is one SSH record: the body a store keeps, filed under the
// coordinates it was stored at.
type Entity[T any] struct {
	ID uint64 `json:"id"`

	// Path is the natural key: the partition root and the record path.
	Path string `json:"path"`

	// Partition is the tenant root ("{tenant}/") the record belongs to.
	Partition string `json:"partition" index:"true"`

	Scope scope.Scope `json:"scope"`
	Owner string      `json:"owner"`
	Name  string      `json:"name"`
	Body  T           `json:"body"`
}

// EntityID returns the entity's ID.
func (e *Entity[T]) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *Entity[T]) SetEntityID(id uint64) { e.ID = id }

// Wiper is implemented by a record body holding secret material. The table
// wipes every record it reads and does not hand to its caller.
type Wiper interface {
	Wipe()
}

// discard wipes e's body when it holds secret material.
func discard[T any](e *Entity[T]) {
	if w, ok := any(&e.Body).(Wiper); ok {
		w.Wipe()
	}
}

// Table is the record table of one kind, viewed through one tenant
// partition. Partition returns views of other partitions sharing the same
// DAO, so a Table is built once and partitioned per request.
type Table[T any] struct {
	records qrdbsdk.GenericDAO[*Entity[T]]
	kind    scope.Kind
	root    string
}

// New returns the table of kind over DatabaseName, viewed through the
// platform partition ("system/").
func New[T any](daos *qrdbsdk.DAOFactory, kind scope.Kind) (*Table[T], error) {
	if !kind.Valid() {
		return nil, &scope.KindInvalidError{Value: string(kind)}
	}
	records, err := dao.New(daos, DatabaseName, "ssh_"+string(kind),
		func() *Entity[T] { return &Entity[T]{} },
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Path")))
	if err != nil {
		return nil, &StoreError{Op: "open", Path: DatabaseName, Err: err}
	}
	t := &Table[T]{records: records, kind: kind}
	return t.Partition("")
}

// Partition returns the view of t through tenantID's partition; "" is the
// platform partition. The view shares t's DAO.
func (t *Table[T]) Partition(tenantID string) (*Table[T], error) {
	root, err := pkgscope.TenantRoot(tenantID)
	if err != nil {
		return nil, err
	}
	return &Table[T]{records: t.records, kind: t.kind, root: root}, nil
}

// Get returns the record of (sc, owner, name). found is false when there is
// none or it is held by another owner.
func (t *Table[T]) Get(ctx context.Context, sc scope.Scope, owner, name string) (e *Entity[T], found bool, err error) {
	path, err := t.path(sc, owner, name)
	if err != nil {
		return nil, false, err
	}
	current, err := t.load(ctx, path)
	if err != nil || current == nil {
		return nil, false, err
	}
	if current.Owner != owner {
		discard(current)
		return nil, false, nil
	}
	return current, true, nil
}

// Create stores body as the record of (sc, owner, name) unless a record
// exists at its path, reporting whether it did. A tenant-scoped record
// exists for every owner.
func (t *Table[T]) Create(ctx context.Context, sc scope.Scope, owner, name string, body T) (bool, error) {
	next, err := t.entity(sc, owner, name, body)
	if err != nil {
		return false, err
	}
	stored, err := t.records.SaveIfAbsent(ctx, next)
	if err != nil {
		return false, &StoreError{Op: "create", Path: next.Path, Err: err}
	}
	return stored, nil
}

// Put stores body as the record of (sc, owner, name), replacing the owner's
// own record. It reports false, storing nothing, when the record at the
// path is held by another owner. Each write is guarded against the record
// it read, so a concurrent writer is never overwritten blindly; a write that
// keeps losing that race is *ConflictError.
func (t *Table[T]) Put(ctx context.Context, sc scope.Scope, owner, name string, body T) (bool, error) {
	next, err := t.entity(sc, owner, name, body)
	if err != nil {
		return false, err
	}
	for range maxAttempts {
		current, err := t.load(ctx, next.Path)
		if err != nil {
			return false, err
		}
		if current == nil {
			stored, err := t.records.SaveIfAbsent(ctx, next)
			if err != nil {
				return false, &StoreError{Op: "put", Path: next.Path, Err: err}
			}
			if stored {
				return true, nil
			}
			continue
		}
		if current.Owner != owner {
			discard(current)
			return false, nil
		}
		next.ID = current.ID
		swapped, err := t.records.CompareAndSwap(ctx, current, next)
		discard(current)
		if err != nil {
			return false, &StoreError{Op: "put", Path: next.Path, Err: err}
		}
		if swapped {
			return true, nil
		}
	}
	return false, &ConflictError{Op: "put", Path: next.Path}
}

// Delete removes the record of (sc, owner, name), reporting false when there
// is none or it is held by another owner. The delete is guarded against the
// record it read; one that keeps losing that race is *ConflictError.
func (t *Table[T]) Delete(ctx context.Context, sc scope.Scope, owner, name string) (bool, error) {
	path, err := t.path(sc, owner, name)
	if err != nil {
		return false, err
	}
	for range maxAttempts {
		current, err := t.load(ctx, path)
		if err != nil || current == nil {
			return false, err
		}
		if current.Owner != owner {
			discard(current)
			return false, nil
		}
		deleted, err := t.records.DeleteIfMatch(ctx, current)
		discard(current)
		if err != nil {
			return false, &StoreError{Op: "delete", Path: path, Err: err}
		}
		if deleted {
			return true, nil
		}
	}
	return false, &ConflictError{Op: "delete", Path: path}
}

// List returns the records of t's partition in scope sc held by owner,
// sorted by path. An empty sc lists every scope, ignoring owner; an empty
// owner lists every owner within sc. scope.ValidateFilter validates the
// filter.
func (t *Table[T]) List(ctx context.Context, sc scope.Scope, owner string) ([]*Entity[T], error) {
	if err := scope.ValidateFilter(sc, owner); err != nil {
		return nil, err
	}
	all, err := t.records.Find(ctx).Where("Partition = ?", t.root).Execute()
	if err != nil {
		return nil, &StoreError{Op: "list", Path: t.root, Err: err}
	}
	out := make([]*Entity[T], 0, len(all))
	for _, e := range all {
		if sc != "" && (e.Scope != sc || (owner != "" && e.Owner != owner)) {
			discard(e)
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// path returns the natural key of the record of (sc, owner, name) in t's
// partition.
func (t *Table[T]) path(sc scope.Scope, owner, name string) (string, error) {
	rel, err := t.kind.RecordPath(sc, owner, name)
	if err != nil {
		return "", err
	}
	return t.root + rel, nil
}

// entity returns the record of (sc, owner, name) holding body.
func (t *Table[T]) entity(sc scope.Scope, owner, name string, body T) (*Entity[T], error) {
	path, err := t.path(sc, owner, name)
	if err != nil {
		return nil, err
	}
	return &Entity[T]{Path: path, Partition: t.root, Scope: sc, Owner: owner, Name: name, Body: body}, nil
}

// load returns the record stored at path, or nil when there is none.
func (t *Table[T]) load(ctx context.Context, path string) (*Entity[T], error) {
	e, err := t.records.GetByNaturalKey(ctx, path)
	if qrdbsdk.IsDAONotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, &StoreError{Op: "get", Path: path, Err: err}
	}
	return e, nil
}
