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

package profile

import (
	"errors"
	"slices"
	"testing"
)

const legacyProfile = `{"id":"p-1","name":"web","folder_path":"prod","host":"web.example.com",` +
	`"created_at":"2026-01-02T03:04:05Z"}`

func TestImportLegacyKeepsTheProfile(t *testing.T) {
	s := newStore(t)
	// Importing twice is harmless: the second import overwrites the first.
	for range 2 {
		if err := s.ImportLegacy(t.Context(), "p-1", []byte(legacyProfile)); err != nil {
			t.Fatalf("ImportLegacy: %v", err)
		}
	}
	got, err := s.Get("p-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != "p-1" || got.Name != "web" || got.Host != "web.example.com" || got.FolderPath != "prod" {
		t.Fatalf("imported profile = %+v", got)
	}
}

func TestImportLegacyRejectsBadRecords(t *testing.T) {
	tests := map[string]string{
		"not json": `{`,
		"other id": `{"id":"p-2","name":"web","host":"h"}`,
		"no host":  `{"id":"p-1","name":"web"}`,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			if err := s.ImportLegacy(t.Context(), "p-1", []byte(data)); !errors.Is(err, ErrLegacyRecord) {
				t.Fatalf("ImportLegacy error = %v, want ErrLegacyRecord", err)
			}
			if _, err := s.Get("p-1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get after a rejected import = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestImportLegacyFolder(t *testing.T) {
	s := newStore(t)
	for range 2 {
		if err := s.ImportLegacyFolder(t.Context(), "prod/web"); err != nil {
			t.Fatalf("ImportLegacyFolder: %v", err)
		}
	}
	folders, err := s.ListFolders()
	if err != nil || !slices.Contains(folders, "prod/web") {
		t.Fatalf("ListFolders = %v, %v", folders, err)
	}
	if err := s.ImportLegacyFolder(t.Context(), ""); !errors.Is(err, ErrFolderEmpty) {
		t.Fatalf("ImportLegacyFolder(\"\") = %v, want ErrFolderEmpty", err)
	}
}

func TestImportLegacyClosedStore(t *testing.T) {
	s := newStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.ImportLegacy(t.Context(), "p-1", []byte(legacyProfile)); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("ImportLegacy error = %v, want ErrStoreClosed", err)
	}
	if err := s.ImportLegacyFolder(t.Context(), "prod"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("ImportLegacyFolder error = %v, want ErrStoreClosed", err)
	}
}
