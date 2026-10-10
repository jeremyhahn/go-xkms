// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package authorized

import (
	"context"
	"strings"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// Store is the persistence interface for authorized_keys Entries.
// Writes take an Entry — the parsed line — while reads return a Record,
// which pairs that Entry with the store metadata (scope, owner, name,
// add time) it was filed under. Implementations MUST be safe for
// concurrent use.
type Store interface {
	// Add persists entry under (scope, owner, name). Returns
	// *DuplicateError if a record already exists at that path — for a
	// tenant-scoped entry, under any owner; non-idempotent by design.
	Add(ctx context.Context, sc scope.Scope, owner, name string, entry *Entry) error

	// Get loads the record at (scope, owner, name). Returns
	// *NotFoundError on miss or when the record is held by another
	// owner. The returned Record carries the stored coordinates, which
	// are authoritative over the arguments.
	Get(ctx context.Context, sc scope.Scope, owner, name string) (*Record, error)

	// List enumerates records under (scope, owner). An empty scope
	// enumerates every scope; an empty owner every owner within scope.
	// Each Record carries the name it was stored under, so a listed
	// record can be fed straight back into Get or Remove.
	List(ctx context.Context, sc scope.Scope, owner string) ([]*Record, error)

	// Remove deletes the entry. Returns *NotFoundError on miss or when
	// the entry is held by another owner.
	Remove(ctx context.Context, sc scope.Scope, owner, name string) error
}

// DAOStore implements Store over go-qrdb DAOs: each entry is a
// records.Entity of kind scope.KindAuthorizedKeys in the records.DatabaseName
// database. A tenant-scoped entry's path carries no owner, so the stored
// Owner is authoritative: an entry held by another owner answers as missing.
type DAOStore struct {
	table *records.Table[envelope]
}

var _ Store = (*DAOStore)(nil)

// envelope is the stored body of an entry. The emitted authorized_keys line
// is kept verbatim and re-parsed on read, so a field added to Entry needs no
// change here.
type envelope struct {
	AddedAt time.Time `json:"added"`
	Line    string    `json:"line"`
}

// NewDAOStore returns the DAOStore over the DAOs daos builds, viewed
// through the platform partition. Errors with *NilInputError if daos is nil.
func NewDAOStore(daos *qrdbsdk.DAOFactory) (*DAOStore, error) {
	if daos == nil {
		return nil, &NilInputError{Field: "daos"}
	}
	table, err := records.New[envelope](daos, scope.KindAuthorizedKeys)
	if err != nil {
		return nil, &StorageError{Op: "open", Err: err}
	}
	return &DAOStore{table: table}, nil
}

// Partition returns the view of s through tenantID's partition ("" is the
// platform partition). The view shares s's DAO.
func (s *DAOStore) Partition(tenantID string) (*DAOStore, error) {
	table, err := s.table.Partition(tenantID)
	if err != nil {
		return nil, err
	}
	return &DAOStore{table: table}, nil
}

// Add implements Store.Add.
func (s *DAOStore) Add(ctx context.Context, sc scope.Scope, owner, name string, entry *Entry) error {
	if err := validate(sc, owner, name); err != nil {
		return err
	}
	if entry == nil {
		return &NilInputError{Field: "entry"}
	}
	line, err := Emit(entry)
	if err != nil {
		return err
	}
	stored, err := s.table.Create(ctx, sc, owner, name, envelope{AddedAt: time.Now().UTC(), Line: line})
	if err != nil {
		return &StorageError{Op: "put", Err: err}
	}
	if !stored {
		return &DuplicateError{Scope: string(sc), Owner: owner, Name: name}
	}
	return nil
}

// Get implements Store.Get.
func (s *DAOStore) Get(ctx context.Context, sc scope.Scope, owner, name string) (*Record, error) {
	if err := validate(sc, owner, name); err != nil {
		return nil, err
	}
	e, found, err := s.table.Get(ctx, sc, owner, name)
	if err != nil {
		return nil, &StorageError{Op: "get", Err: err}
	}
	if !found {
		return nil, &NotFoundError{Scope: string(sc), Owner: owner, Name: name}
	}
	return record(e)
}

// List implements Store.List. Records are returned in path order.
func (s *DAOStore) List(ctx context.Context, sc scope.Scope, owner string) ([]*Record, error) {
	if err := scope.ValidateFilter(sc, owner); err != nil {
		return nil, err
	}
	entities, err := s.table.List(ctx, sc, owner)
	if err != nil {
		return nil, &StorageError{Op: "list", Err: err}
	}
	out := make([]*Record, 0, len(entities))
	for _, e := range entities {
		rec, err := record(e)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// Remove implements Store.Remove.
func (s *DAOStore) Remove(ctx context.Context, sc scope.Scope, owner, name string) error {
	if err := validate(sc, owner, name); err != nil {
		return err
	}
	deleted, err := s.table.Delete(ctx, sc, owner, name)
	if err != nil {
		return &StorageError{Op: "delete", Err: err}
	}
	if !deleted {
		return &NotFoundError{Scope: string(sc), Owner: owner, Name: name}
	}
	return nil
}

// validate checks the coordinates of an entry. The name is validated first
// so a malformed name reports *InvalidNameError; the rest is validated as
// scope.KindAuthorizedKeys.RecordPath validates it.
func validate(sc scope.Scope, owner, name string) error {
	if !sc.Valid() {
		return &scope.ScopeInvalidError{Value: string(sc)}
	}
	if err := validateName(name); err != nil {
		return err
	}
	_, err := scope.KindAuthorizedKeys.RecordPath(sc, owner, name)
	return err
}

// validateName refuses an empty name or one containing '/' or NUL.
func validateName(name string) error {
	if name == "" {
		return &InvalidNameError{Value: name, Reason: "empty"}
	}
	if strings.ContainsRune(name, '/') {
		return &InvalidNameError{Value: name, Reason: "contains path separator"}
	}
	if strings.ContainsRune(name, 0) {
		return &InvalidNameError{Value: name, Reason: "contains NUL byte"}
	}
	return nil
}

// record rehydrates the *Record e stores: the Entry comes from re-parsing
// the stored authorized_keys line, the coordinates from the record.
func record(e *records.Entity[envelope]) (*Record, error) {
	entry, err := ParseLine(e.Body.Line)
	if err != nil {
		return nil, err
	}
	return &Record{
		Scope:   e.Scope,
		Owner:   e.Owner,
		Name:    e.Name,
		AddedAt: e.Body.AddedAt,
		Entry:   entry,
	}, nil
}
