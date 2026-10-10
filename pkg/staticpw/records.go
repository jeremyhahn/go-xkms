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

package staticpw

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/aesgcm"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
)

// DatabaseName is the go-qrdb database the platform's password records live
// in. A composition root opens it on the datastore before building the
// system store; a tenant's records live in the store its tenant resolves to.
const DatabaseName = "staticpw"

// recordEntityType is the go-qrdb entity type of every password record.
const recordEntityType = "staticpw_records"

// maxAttempts bounds the read-compare-write retries of one write racing
// concurrent writers of the same record.
const maxAttempts = 16

// dekAADPrefix binds a personal record's ciphertext to its path, so a body
// moved to another path (another user's, another entry's) does not open.
const dekAADPrefix = "xkms/staticpw/personal/v1|"

// record is one password-manager record -- an entry, a folder marker, an
// alias or a vault factor -- filed under the directory of its store.
type record struct {
	ID uint64 `json:"id"`

	// Path is the natural key: Dir followed by the record's name.
	Path string `json:"path"`

	// Dir is the store prefix and record kind the record is listed under.
	Dir string `json:"dir" index:"true"`

	// Body is the record's value, sealed with the user's DEK in a personal
	// store.
	Body []byte `json:"body"`
}

// EntityID returns the record's ID.
func (r *record) EntityID() uint64 { return r.ID }

// SetEntityID sets the record's ID.
func (r *record) SetEntityID(id uint64) { r.ID = id }

// records is the password record table over one DAO factory.
type records struct {
	dao qrdbsdk.GenericDAO[*record]
}

// openRecords returns the record table of DatabaseName on daos.
func openRecords(daos *qrdbsdk.DAOFactory) (*records, error) {
	d, err := dao.New(daos, DatabaseName, recordEntityType,
		func() *record { return &record{} },
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Path")))
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}
	return &records{dao: d}, nil
}

// load returns the record at path, or nil when there is none.
func (t *records) load(ctx context.Context, path string) (*record, error) {
	r, err := t.dao.GetByNaturalKey(ctx, path)
	if qrdbsdk.IsDAONotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, &StoreError{Op: "get", Key: path, Err: err}
	}
	return r, nil
}

// create stores r unless a record exists at its path, reporting whether it
// did.
func (t *records) create(ctx context.Context, r *record) (bool, error) {
	stored, err := t.dao.SaveIfAbsent(ctx, r)
	if err != nil {
		return false, &StoreError{Op: "create", Key: r.Path, Err: err}
	}
	return stored, nil
}

// put stores r, replacing the record at its path. Each write is guarded
// against the record it read; one that keeps losing that race is
// *ConflictError.
func (t *records) put(ctx context.Context, r *record) error {
	for range maxAttempts {
		current, err := t.load(ctx, r.Path)
		if err != nil {
			return err
		}
		if current == nil {
			stored, err := t.create(ctx, r)
			if err != nil || stored {
				return err
			}
			continue
		}
		swapped, err := t.swap(ctx, current, r)
		if err != nil || swapped {
			return err
		}
	}
	return &ConflictError{Op: "put", Key: r.Path}
}

// swap replaces current with next, which share a path, unless the stored
// record no longer matches current.
func (t *records) swap(ctx context.Context, current, next *record) (bool, error) {
	next.ID = current.ID
	swapped, err := t.dao.CompareAndSwap(ctx, current, next)
	if err != nil {
		return false, &StoreError{Op: "swap", Key: next.Path, Err: err}
	}
	return swapped, nil
}

// remove deletes the record at path, reporting false when there is none.
// The delete is guarded against the record it read; one that keeps losing
// that race is *ConflictError.
func (t *records) remove(ctx context.Context, path string) (bool, error) {
	for range maxAttempts {
		current, err := t.load(ctx, path)
		if err != nil || current == nil {
			return false, err
		}
		deleted, err := t.removeIfMatch(ctx, current)
		if err != nil || deleted {
			return deleted, err
		}
	}
	return false, &ConflictError{Op: "delete", Key: path}
}

// removeIfMatch deletes current unless the stored record no longer matches
// it.
func (t *records) removeIfMatch(ctx context.Context, current *record) (bool, error) {
	deleted, err := t.dao.DeleteIfMatch(ctx, current)
	if err != nil {
		return false, &StoreError{Op: "delete", Key: current.Path, Err: err}
	}
	return deleted, nil
}

// rename stores next at its own path and removes current, which is held at
// another path. It reports ErrPasswordExists when next's path is taken, and
// *ConflictError, undoing the write, when current changed meanwhile.
func (t *records) rename(ctx context.Context, current, next *record) error {
	stored, err := t.create(ctx, next)
	if err != nil {
		return err
	}
	if !stored {
		return ErrPasswordExists
	}
	deleted, err := t.removeIfMatch(ctx, current)
	if err == nil && deleted {
		return nil
	}
	if _, undoErr := t.removeIfMatch(ctx, next); undoErr != nil {
		return undoErr
	}
	if err != nil {
		return err
	}
	return &ConflictError{Op: "rename", Key: current.Path}
}

// list returns the records listed under dir.
func (t *records) list(ctx context.Context, dir string) ([]*record, error) {
	all, err := t.dao.Find(ctx).Where("Dir = ?", dir).Execute()
	if err != nil {
		return nil, &StoreError{Op: "list", Key: dir, Err: err}
	}
	return all, nil
}

// sealer seals the bodies of a personal store's records with the DEK of the
// user's session (AES-256-GCM, the record path as associated data). Once the
// session ends it seals and opens nothing: ErrStoreLocked. A nil session --
// the system and shared stores -- leaves bodies as they are; the tenant's
// barrier encrypts them at rest.
type sealer struct {
	session *userSession
}

// seal returns body as stored at path.
func (s sealer) seal(path string, body []byte) ([]byte, error) {
	if s.session == nil {
		return body, nil
	}
	var ct []byte
	err := s.session.withDEK(func(dek []byte) error {
		var err error
		ct, err = aesgcm.EncryptWithAAD(dek, body, []byte(dekAADPrefix+path))
		if err != nil {
			return &VaultCryptoError{Op: "seal entry", Err: err}
		}
		return nil
	})
	return ct, err
}

// open returns the body stored at path.
func (s sealer) open(path string, body []byte) ([]byte, error) {
	if s.session == nil {
		return body, nil
	}
	var pt []byte
	err := s.session.withDEK(func(dek []byte) error {
		var err error
		pt, err = aesgcm.DecryptWithAAD(dek, body, []byte(dekAADPrefix+path))
		if err != nil {
			return &PersonalEntryDecryptError{Key: path, Err: err}
		}
		return nil
	})
	return pt, err
}

// PersonalEntryDecryptError reports a personal record the user's DEK does
// not open: it was written under another key, or tampered with.
type PersonalEntryDecryptError struct {
	Key string
	Err error
}

// Error implements the error interface.
func (e *PersonalEntryDecryptError) Error() string {
	return "staticpw: personal entry " + e.Key + " does not open with the user's key: " + e.Err.Error()
}

// Unwrap returns the underlying failure.
func (e *PersonalEntryDecryptError) Unwrap() error { return e.Err }
