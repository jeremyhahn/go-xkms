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

package sessions

import (
	"errors"
	"testing"
	"time"
)

const legacySession = `{"id":"abc123","title":"alice@example.com","host":"example.com","port":22,` +
	`"user":"alice","created_at":"2026-01-02T03:04:05Z","last_connected_at":"2026-01-03T03:04:05Z"}`

func TestImportLegacyKeepsTheSession(t *testing.T) {
	s := newTestStore(t)
	// Importing twice is harmless: the second import overwrites the first.
	for range 2 {
		if err := s.ImportLegacy(t.Context(), "abc123", []byte(legacySession)); err != nil {
			t.Fatalf("ImportLegacy: %v", err)
		}
	}
	got, err := s.Get("abc123")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if got.Title != "alice@example.com" || got.Port != 22 || !got.CreatedAt.Equal(created) {
		t.Fatalf("imported session = %+v", got)
	}
	all, err := s.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("List = %d sessions, %v", len(all), err)
	}
}

func TestImportLegacyRejectsBadRecords(t *testing.T) {
	tests := map[string]string{
		"not json":  `{`,
		"other id":  `{"id":"zzz","title":"t","host":"h"}`,
		"no origin": `{"id":"abc123","title":"t"}`,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.ImportLegacy(t.Context(), "abc123", []byte(data)); !errors.Is(err, ErrLegacyRecord) {
				t.Fatalf("ImportLegacy error = %v, want ErrLegacyRecord", err)
			}
			if _, err := s.Get("abc123"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get after a rejected import = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestImportLegacyClosedStore(t *testing.T) {
	s := newTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.ImportLegacy(t.Context(), "abc123", []byte(legacySession)); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("ImportLegacy error = %v, want ErrStoreClosed", err)
	}
}
