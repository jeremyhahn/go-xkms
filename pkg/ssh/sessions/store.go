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

package sessions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/records"
)

// entityType is the go-qrdb entity type of a session record.
const entityType = "ssh_sessions"

// Store is the persistence interface for embedded-console session records.
// Implementations MUST be safe for concurrent use.
type Store interface {
	// Save persists a record, assigning a fresh random ID when empty and
	// stamping CreatedAt on first save. An existing ID is overwritten.
	Save(s *Session) error
	Get(id string) (*Session, error)
	List() ([]*Session, error)
	Delete(id string) error
	Close() error
}

// record is one stored session, keyed by its session ID.
type record struct {
	ID      uint64  `json:"id"`
	Key     string  `json:"key"`
	Session Session `json:"session"`
}

// EntityID returns the record's ID.
func (r *record) EntityID() uint64 { return r.ID }

// SetEntityID sets the record's ID.
func (r *record) SetEntityID(id uint64) { r.ID = id }

// DAOStore implements Store as go-qrdb entities in the records.DatabaseName
// database.
type DAOStore struct {
	records qrdbsdk.GenericDAO[*record]
	closed  atomic.Bool
}

var _ Store = (*DAOStore)(nil)

// NewStore constructs the DAOStore over the DAOs daos builds. Returns
// ErrNilDAOFactory if daos is nil.
func NewStore(daos *qrdbsdk.DAOFactory) (*DAOStore, error) {
	if daos == nil {
		return nil, ErrNilDAOFactory
	}
	sessions, err := dao.New(daos, records.DatabaseName, entityType,
		func() *record { return &record{} },
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Key")))
	if err != nil {
		return nil, &errs.Joined{Lead: ErrStorage, Detail: "open", Cause: err}
	}
	return &DAOStore{records: sessions}, nil
}

// Save persists a session record (see Store.Save).
func (s *DAOStore) Save(sess *Session) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}
	if err := sess.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	if sess.ID == "" {
		id, err := randomID()
		if err != nil {
			return err
		}
		sess.ID = id
		sess.CreatedAt = now
	}
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = now
	}
	if sess.LastConnectedAt.IsZero() {
		sess.LastConnectedAt = now
	}
	if err := s.records.Save(context.Background(), &record{Key: sess.ID, Session: *sess}); err != nil {
		return &errs.Joined{Lead: ErrStorage, Detail: "save " + sess.ID, Cause: err}
	}
	return nil
}

// Get retrieves a session record by ID.
func (s *DAOStore) Get(id string) (*Session, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}
	r, err := s.load(id)
	if err != nil {
		return nil, err
	}
	return &r.Session, nil
}

// List returns all session records, most recently connected first.
func (s *DAOStore) List() ([]*Session, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}
	all, err := s.records.Find(context.Background()).Execute()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrStorage, Detail: "list", Cause: err}
	}
	out := make([]*Session, 0, len(all))
	for _, r := range all {
		out = append(out, &r.Session)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastConnectedAt.After(out[j].LastConnectedAt)
	})
	return out, nil
}

// Delete removes a session record by ID.
func (s *DAOStore) Delete(id string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}
	r, err := s.load(id)
	if err != nil {
		return err
	}
	if err := s.records.Delete(context.Background(), r); err != nil {
		return &errs.Joined{Lead: ErrStorage, Detail: "delete " + id, Cause: err}
	}
	return nil
}

// Close marks the store closed; subsequent operations fail with
// ErrStoreClosed. The DAO factory is owned by the caller.
func (s *DAOStore) Close() error {
	s.closed.Store(true)
	return nil
}

// load returns the record of session id, or ErrNotFound.
func (s *DAOStore) load(id string) (*record, error) {
	r, err := s.records.GetByNaturalKey(context.Background(), id)
	if qrdbsdk.IsDAONotFound(err) {
		return nil, &errs.Detail{Err: ErrNotFound, Detail: id}
	}
	if err != nil {
		return nil, &errs.Joined{Lead: ErrStorage, Detail: "get " + id, Cause: err}
	}
	return r, nil
}

// randomID returns a 16-hex-char random session identifier.
func randomID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", &errs.Joined{Lead: ErrRandomID, Cause: err}
	}
	return hex.EncodeToString(b), nil
}
