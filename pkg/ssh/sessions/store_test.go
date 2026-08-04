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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func newTestStore(t *testing.T) *BackendStore {
	t.Helper()
	s, err := NewStore(storage.New())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

func TestNewStore_NilBackend(t *testing.T) {
	if _, err := NewStore(nil); !errors.Is(err, ErrNilBackend) {
		t.Fatalf("expected ErrNilBackend, got %v", err)
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
	sess.LastConnectedAt = time.Now().UTC().Add(time.Hour)
	if err := s.Save(sess); err != nil {
		t.Fatalf("Save (update): %v", err)
	}
	all, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("update must not duplicate, got %d records", len(all))
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
