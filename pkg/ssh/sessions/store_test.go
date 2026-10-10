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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

func newTestStore(t *testing.T) *DAOStore {
	t.Helper()
	s, err := NewStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

// storeOver returns the DAOStore over backend.
func storeOver(t *testing.T, backend storage.Backend) *DAOStore {
	t.Helper()
	kv, err := kvadapter.New(backend)
	if err != nil {
		t.Fatalf("kvadapter.New: %v", err)
	}
	s, err := NewStore(dao.NewStoreFactory(kv))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

func TestNewStore_NilDAOFactory(t *testing.T) {
	if _, err := NewStore(nil); !errors.Is(err, ErrNilDAOFactory) {
		t.Fatalf("expected ErrNilDAOFactory, got %v", err)
	}
}

func TestSessionStore_SaveAssignsIDAndTimestamps(t *testing.T) {
	s := newTestStore(t)
	sess := &Session{Title: "deploy@web1", Host: "web1", Port: 22, User: "deploy"}
	if err := s.Save(sess); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if len(sess.ID) != 16 {
		t.Fatalf("expected 16-hex random ID, got %q", sess.ID)
	}
	if sess.CreatedAt.IsZero() || sess.LastConnectedAt.IsZero() {
		t.Fatalf("timestamps not stamped: %+v", sess)
	}

	got, err := s.Get(sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Title != "deploy@web1" || got.Host != "web1" || got.User != "deploy" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestSessionStore_SaveValidation(t *testing.T) {
	s := newTestStore(t)
	if err := s.Save(&Session{Host: "h"}); !errors.Is(err, ErrInvalidTitle) {
		t.Fatalf("expected ErrInvalidTitle, got %v", err)
	}
	if err := s.Save(&Session{Title: "t"}); !errors.Is(err, ErrInvalidOrigin) {
		t.Fatalf("expected ErrInvalidOrigin for no origin, got %v", err)
	}
	if err := s.Save(&Session{Title: "t", Host: "h", ProfileID: "p"}); !errors.Is(err, ErrInvalidOrigin) {
		t.Fatalf("expected ErrInvalidOrigin for two origins, got %v", err)
	}
}

func TestSessionStore_SaveOverwritesExisting(t *testing.T) {
	s := newTestStore(t)
	sess := &Session{Title: "t", ProfileID: "profile-1"}
	if err := s.Save(sess); err != nil {
		t.Fatalf("Save: %v", err)
	}
	sess.Title = "renamed"
	if err := s.Save(sess); err != nil {
		t.Fatalf("Save (update): %v", err)
	}
	all, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 || all[0].Title != "renamed" {
		t.Fatalf("update must replace the one record, got %+v", all)
	}
}

func TestSessionStore_ListSortsByLastConnected(t *testing.T) {
	s := newTestStore(t)
	older := &Session{Title: "older", Alias: "a", LastConnectedAt: time.Now().UTC().Add(-time.Hour)}
	newer := &Session{Title: "newer", Alias: "b", LastConnectedAt: time.Now().UTC()}
	for _, sess := range []*Session{older, newer} {
		if err := s.Save(sess); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	all, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 || all[0].Title != "newer" || all[1].Title != "older" {
		t.Fatalf("expected most-recent-first order, got %+v", all)
	}
}

func TestSessionStore_GetNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSessionStore_DeleteAndNotFound(t *testing.T) {
	s := newTestStore(t)
	sess := &Session{Title: "t", Host: "h"}
	if err := s.Save(sess); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.Delete(sess.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(sess.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if err := s.Delete(sess.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for double delete, got %v", err)
	}
}

func TestSessionStore_ClosedStoreFailsEverything(t *testing.T) {
	s := newTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Save(&Session{Title: "t", Host: "h"}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Save on closed store: %v", err)
	}
	if _, err := s.Get("x"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Get on closed store: %v", err)
	}
	if _, err := s.List(); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("List on closed store: %v", err)
	}
	if err := s.Delete("x"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Delete on closed store: %v", err)
	}
}

func TestSessionStore_StorageErrors(t *testing.T) {
	s := storeOver(t, failingBackend{})
	if err := s.Save(&Session{Title: "t", Host: "h"}); !errors.Is(err, ErrStorage) || !errors.Is(err, errInjected) {
		t.Fatalf("Save: want ErrStorage wrapping the cause, got %v", err)
	}
	if _, err := s.Get("x"); !errors.Is(err, ErrStorage) {
		t.Fatalf("Get: want ErrStorage, got %v", err)
	}
	if _, err := s.List(); !errors.Is(err, ErrStorage) {
		t.Fatalf("List: want ErrStorage, got %v", err)
	}
	if err := s.Delete("x"); !errors.Is(err, ErrStorage) {
		t.Fatalf("Delete: want ErrStorage, got %v", err)
	}
}

// TestSessionStore_DeleteStorageError proves a failed delete of a record
// that exists is reported, not swallowed.
func TestSessionStore_DeleteStorageError(t *testing.T) {
	backend := &deleteFailingBackend{Backend: storage.New()}
	s := storeOver(t, backend)
	sess := &Session{Title: "t", Host: "h"}
	if err := s.Save(sess); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.Delete(sess.ID); !errors.Is(err, ErrStorage) {
		t.Fatalf("Delete: want ErrStorage, got %v", err)
	}
}

var errInjected = errors.New("injected backend failure")

// failingBackend is a storage.Backend whose operations always fail. It
// implements the guarded writes, so the DAO over it is atomic and every
// failure is the backend's.
type failingBackend struct{}

func (failingBackend) Get(_ context.Context, _ string) ([]byte, error) { return nil, errInjected }
func (failingBackend) Put(_ context.Context, _ string, _ []byte) error { return errInjected }
func (failingBackend) PutIfAbsent(_ context.Context, _ string, _ []byte) (bool, error) {
	return false, errInjected
}
func (failingBackend) CompareAndSwap(_ context.Context, _ string, _, _ []byte) (bool, []byte, error) {
	return false, nil, errInjected
}
func (failingBackend) CompareAndDelete(_ context.Context, _ string, _ []byte) (bool, error) {
	return false, errInjected
}
func (failingBackend) Delete(_ context.Context, _ string) error { return errInjected }
func (failingBackend) List(_ context.Context, _ string) ([]string, error) {
	return nil, errInjected
}
func (failingBackend) Scan(_ context.Context, _ string, _ func(string, []byte) error) error {
	return errInjected
}
func (failingBackend) Exists(_ context.Context, _ string) (bool, error) { return false, errInjected }
func (failingBackend) Close() error                                     { return nil }

// deleteFailingBackend is a working backend whose deletes fail.
type deleteFailingBackend struct{ storage.Backend }

func (b *deleteFailingBackend) Delete(_ context.Context, _ string) error { return errInjected }
func (b *deleteFailingBackend) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, []byte, error) {
	return b.Backend.(storage.CompareAndSwapper).CompareAndSwap(ctx, key, expected, next)
}
func (b *deleteFailingBackend) CompareAndDelete(_ context.Context, _ string, _ []byte) (bool, error) {
	return false, errInjected
}
