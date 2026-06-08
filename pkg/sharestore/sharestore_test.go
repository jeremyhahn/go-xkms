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

package sharestore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func sampleEntry() *ShareEntry {
	return &ShareEntry{
		ServerURL:  "https://xkms.example.com",
		GroupID:    "group-1",
		GroupName:  "Test Group",
		ShareIndex: 1,
		ShareData:  []byte("secret-share-data"),
		Purpose:    "barrier",
		ReceivedAt: time.Now().UTC(),
		TenantID:   "tenant-a",
	}
}

func TestShareEntry_Validate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ShareEntry)
		want   error
	}{
		{"valid", func(*ShareEntry) {}, nil},
		{"nil server url", func(e *ShareEntry) { e.ServerURL = "" }, ErrInvalidServerURL},
		{"nil group id", func(e *ShareEntry) { e.GroupID = "" }, ErrInvalidGroupID},
		{"empty share data", func(e *ShareEntry) { e.ShareData = nil }, ErrEmptyShareData},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := sampleEntry()
			tc.mutate(e)
			if err := e.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("Validate() = %v, want %v", err, tc.want)
			}
		})
	}

	if err := (*ShareEntry)(nil).Validate(); !errors.Is(err, ErrInvalidShare) {
		t.Fatalf("nil entry Validate() = %v, want ErrInvalidShare", err)
	}
}

func TestNewBackendShareStore_NilBackend(t *testing.T) {
	if _, err := NewBackendShareStore(nil, ""); !errors.Is(err, ErrNilStorage) {
		t.Fatalf("expected ErrNilStorage, got %v", err)
	}
}

// runStoreContract exercises the ShareStore contract against any implementation.
func runStoreContract(t *testing.T, store ShareStore) {
	t.Helper()
	ctx := context.Background()
	entry := sampleEntry()

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Duplicate save is rejected.
	if err := store.Save(ctx, entry); !errors.Is(err, ErrShareExists) {
		t.Fatalf("duplicate Save = %v, want ErrShareExists", err)
	}

	// Invalid entry is rejected before storage.
	if err := store.Save(ctx, &ShareEntry{GroupID: "g", ShareData: []byte("x")}); !errors.Is(err, ErrInvalidServerURL) {
		t.Fatalf("invalid Save = %v, want ErrInvalidServerURL", err)
	}

	loaded, err := store.Load(ctx, entry.ServerURL, entry.GroupID, entry.ShareIndex)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(loaded.ShareData) != string(entry.ShareData) || loaded.GroupName != entry.GroupName {
		t.Fatalf("Load returned %+v, want %+v", loaded, entry)
	}

	// Second entry in the same group, different index.
	second := sampleEntry()
	second.ShareIndex = 2
	if err := store.Save(ctx, second); err != nil {
		t.Fatalf("Save second: %v", err)
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List len = %d, want 2", len(list))
	}
	if list[0].ShareIndex != 1 || list[1].ShareIndex != 2 {
		t.Fatalf("List not ordered by index: %d, %d", list[0].ShareIndex, list[1].ShareIndex)
	}

	if err := store.Delete(ctx, entry.ServerURL, entry.GroupID, entry.ShareIndex); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Load(ctx, entry.ServerURL, entry.GroupID, entry.ShareIndex); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("Load after delete = %v, want ErrShareNotFound", err)
	}
	if err := store.Delete(ctx, entry.ServerURL, entry.GroupID, entry.ShareIndex); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("Delete missing = %v, want ErrShareNotFound", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestBackendShareStore_Contract(t *testing.T) {
	store, err := NewBackendShareStore(storage.NewMemory(), "shamir/")
	if err != nil {
		t.Fatalf("NewBackendShareStore: %v", err)
	}
	runStoreContract(t, store)
}

func TestMemoryShareStore_Contract(t *testing.T) {
	runStoreContract(t, NewMemoryShareStore())
}
