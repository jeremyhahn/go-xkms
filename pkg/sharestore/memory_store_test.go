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
)

func newTestMemoryStore() *MemoryShareStore {
	return NewMemoryShareStore()
}

func newTestMemoryEntry() *ShareEntry {
	return &ShareEntry{
		ServerURL:  "https://xkms.example.com",
		GroupID:    "custodians-1",
		GroupName:  "Primary Custodians",
		ShareIndex: 1,
		ShareData:  []byte("secret-share-data"),
		Purpose:    "barrier",
	}
}

// --- NewMemoryShareStore ---

func TestNewMemoryShareStore(t *testing.T) {
	store := NewMemoryShareStore()
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if store.shares == nil {
		t.Fatal("expected non-nil shares map")
	}
}

// --- Save ---

func TestMemoryShareStore_Save_Success(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()
	entry := newTestMemoryEntry()

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	// Verify ReceivedAt was set.
	stored := store.shares[entry.Key()]
	if stored.ReceivedAt.IsZero() {
		t.Fatal("expected ReceivedAt to be set")
	}
}

func TestMemoryShareStore_Save_PreservesReceivedAt(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()
	entry := newTestMemoryEntry()
	fixedTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	entry.ReceivedAt = fixedTime

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	loaded, err := store.Load(ctx, entry.ServerURL, entry.GroupID, entry.ShareIndex)
	if err != nil {
		t.Fatalf("expected nil error on load, got: %v", err)
	}
	if !loaded.ReceivedAt.Equal(fixedTime) {
		t.Fatalf("expected ReceivedAt %v, got %v", fixedTime, loaded.ReceivedAt)
	}
}

func TestMemoryShareStore_Save_DeepCopy(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()
	entry := newTestMemoryEntry()

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	// Mutate the original entry's share data.
	entry.ShareData[0] = 0xFF

	// Verify stored data is unaffected.
	loaded, err := store.Load(ctx, entry.ServerURL, entry.GroupID, entry.ShareIndex)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if loaded.ShareData[0] == 0xFF {
		t.Fatal("stored share data was mutated by external modification")
	}
}

func TestMemoryShareStore_Save_NilEntry(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	err := store.Save(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil entry, got nil")
	}
	if !errors.Is(err, ErrNilEntry) {
		t.Fatalf("expected ErrNilEntry, got: %v", err)
	}
}

func TestMemoryShareStore_Save_InvalidEntry(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	entry := &ShareEntry{
		ServerURL: "",
		GroupID:   "group-1",
		ShareData: []byte("data"),
	}

	err := store.Save(ctx, entry)
	if err == nil {
		t.Fatal("expected error for invalid entry, got nil")
	}
	if !errors.Is(err, ErrInvalidServerURL) {
		t.Fatalf("expected ErrInvalidServerURL, got: %v", err)
	}
}

func TestMemoryShareStore_Save_Duplicate(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()
	entry := newTestMemoryEntry()

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("expected nil error on first save, got: %v", err)
	}

	entry2 := newTestMemoryEntry()
	err := store.Save(ctx, entry2)
	if err == nil {
		t.Fatal("expected error for duplicate entry, got nil")
	}
	if !errors.Is(err, ErrShareExists) {
		t.Fatalf("expected ErrShareExists, got: %v", err)
	}
}

func TestMemoryShareStore_Save_Closed(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	if err := store.Close(); err != nil {
		t.Fatalf("failed to close store: %v", err)
	}

	err := store.Save(ctx, newTestMemoryEntry())
	if err == nil {
		t.Fatal("expected error on closed store, got nil")
	}
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got: %v", err)
	}
}

// --- Load ---

func TestMemoryShareStore_Load_Success(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()
	entry := newTestMemoryEntry()

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	loaded, err := store.Load(ctx, entry.ServerURL, entry.GroupID, entry.ShareIndex)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if loaded.ServerURL != entry.ServerURL {
		t.Fatalf("expected server URL %q, got %q", entry.ServerURL, loaded.ServerURL)
	}
	if loaded.GroupID != entry.GroupID {
		t.Fatalf("expected group ID %q, got %q", entry.GroupID, loaded.GroupID)
	}
	if string(loaded.ShareData) != "secret-share-data" {
		t.Fatalf("expected share data %q, got %q", "secret-share-data", loaded.ShareData)
	}
}

func TestMemoryShareStore_Load_DeepCopy(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()
	entry := newTestMemoryEntry()

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	loaded, err := store.Load(ctx, entry.ServerURL, entry.GroupID, entry.ShareIndex)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	// Mutate loaded data.
	loaded.ShareData[0] = 0xFF

	// Re-load and verify original is unaffected.
	reloaded, err := store.Load(ctx, entry.ServerURL, entry.GroupID, entry.ShareIndex)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if reloaded.ShareData[0] == 0xFF {
		t.Fatal("stored share data was mutated through loaded copy")
	}
}

func TestMemoryShareStore_Load_NotFound(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	_, err := store.Load(ctx, "https://nonexistent.com", "group-1", 1)
	if err == nil {
		t.Fatal("expected error for non-existent share, got nil")
	}
	if !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("expected ErrShareNotFound, got: %v", err)
	}
}

func TestMemoryShareStore_Load_EmptyServerURL(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	_, err := store.Load(ctx, "", "group-1", 1)
	if err == nil {
		t.Fatal("expected error for empty server URL, got nil")
	}
	if !errors.Is(err, ErrInvalidServerURL) {
		t.Fatalf("expected ErrInvalidServerURL, got: %v", err)
	}
}

func TestMemoryShareStore_Load_EmptyGroupID(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	_, err := store.Load(ctx, "https://xkms.example.com", "", 1)
	if err == nil {
		t.Fatal("expected error for empty group ID, got nil")
	}
	if !errors.Is(err, ErrInvalidGroupID) {
		t.Fatalf("expected ErrInvalidGroupID, got: %v", err)
	}
}

func TestMemoryShareStore_Load_Closed(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	if err := store.Close(); err != nil {
		t.Fatalf("failed to close store: %v", err)
	}

	_, err := store.Load(ctx, "https://xkms.example.com", "group-1", 1)
	if err == nil {
		t.Fatal("expected error on closed store, got nil")
	}
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got: %v", err)
	}
}

// --- Delete ---

func TestMemoryShareStore_Delete_Success(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()
	entry := newTestMemoryEntry()

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	if err := store.Delete(ctx, entry.ServerURL, entry.GroupID, entry.ShareIndex); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	_, err := store.Load(ctx, entry.ServerURL, entry.GroupID, entry.ShareIndex)
	if !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("expected ErrShareNotFound after delete, got: %v", err)
	}
}

func TestMemoryShareStore_Delete_NotFound(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	err := store.Delete(ctx, "https://nonexistent.com", "group-1", 1)
	if err == nil {
		t.Fatal("expected error for non-existent share, got nil")
	}
	if !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("expected ErrShareNotFound, got: %v", err)
	}
}

func TestMemoryShareStore_Delete_EmptyServerURL(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	err := store.Delete(ctx, "", "group-1", 1)
	if err == nil {
		t.Fatal("expected error for empty server URL, got nil")
	}
	if !errors.Is(err, ErrInvalidServerURL) {
		t.Fatalf("expected ErrInvalidServerURL, got: %v", err)
	}
}

func TestMemoryShareStore_Delete_EmptyGroupID(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	err := store.Delete(ctx, "https://xkms.example.com", "", 1)
	if err == nil {
		t.Fatal("expected error for empty group ID, got nil")
	}
	if !errors.Is(err, ErrInvalidGroupID) {
		t.Fatalf("expected ErrInvalidGroupID, got: %v", err)
	}
}

func TestMemoryShareStore_Delete_Closed(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	if err := store.Close(); err != nil {
		t.Fatalf("failed to close store: %v", err)
	}

	err := store.Delete(ctx, "https://xkms.example.com", "group-1", 1)
	if err == nil {
		t.Fatal("expected error on closed store, got nil")
	}
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got: %v", err)
	}
}

// --- List ---

func TestMemoryShareStore_List_Empty(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	entries, err := store.List(ctx)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestMemoryShareStore_List_MultipleSorted(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	entries := []*ShareEntry{
		{
			ServerURL:  "https://server-b.com",
			GroupID:    "group-2",
			ShareIndex: 1,
			ShareData:  []byte("share-b"),
		},
		{
			ServerURL:  "https://server-a.com",
			GroupID:    "group-1",
			ShareIndex: 1,
			ShareData:  []byte("share-a"),
		},
		{
			ServerURL:  "https://server-a.com",
			GroupID:    "group-2",
			ShareIndex: 1,
			ShareData:  []byte("share-c"),
		},
	}

	for _, e := range entries {
		if err := store.Save(ctx, e); err != nil {
			t.Fatalf("failed to save: %v", err)
		}
	}

	result, err := store.List(ctx)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(result))
	}

	for i := 0; i < len(result)-1; i++ {
		if result[i].Key() >= result[i+1].Key() {
			t.Fatalf("entries not sorted: %q >= %q", result[i].Key(), result[i+1].Key())
		}
	}
}

func TestMemoryShareStore_List_DeepCopy(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	entry := newTestMemoryEntry()
	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	result, err := store.List(ctx)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	// Mutate listed entry.
	result[0].ShareData[0] = 0xFF

	// Re-list and verify original is unaffected.
	result2, err := store.List(ctx)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if result2[0].ShareData[0] == 0xFF {
		t.Fatal("stored share data was mutated through listed copy")
	}
}

func TestMemoryShareStore_List_Closed(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	if err := store.Close(); err != nil {
		t.Fatalf("failed to close store: %v", err)
	}

	_, err := store.List(ctx)
	if err == nil {
		t.Fatal("expected error on closed store, got nil")
	}
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got: %v", err)
	}
}

// --- ListByServer ---

func TestMemoryShareStore_ListByServer_Found(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	entries := []*ShareEntry{
		{
			ServerURL:  "https://server-a.com",
			GroupID:    "group-1",
			ShareIndex: 1,
			ShareData:  []byte("share-1"),
		},
		{
			ServerURL:  "https://server-a.com",
			GroupID:    "group-2",
			ShareIndex: 1,
			ShareData:  []byte("share-2"),
		},
		{
			ServerURL:  "https://server-b.com",
			GroupID:    "group-1",
			ShareIndex: 1,
			ShareData:  []byte("share-3"),
		},
	}

	for _, e := range entries {
		if err := store.Save(ctx, e); err != nil {
			t.Fatalf("failed to save: %v", err)
		}
	}

	result, err := store.ListByServer(ctx, "https://server-a.com")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 entries for server-a, got %d", len(result))
	}
	for _, e := range result {
		if e.ServerURL != "https://server-a.com" {
			t.Fatalf("expected server URL https://server-a.com, got %q", e.ServerURL)
		}
	}
}

func TestMemoryShareStore_ListByServer_NotFound(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	entry := newTestMemoryEntry()
	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	result, err := store.ListByServer(ctx, "https://nonexistent.com")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(result))
	}
}

func TestMemoryShareStore_ListByServer_EmptyServerURL(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	_, err := store.ListByServer(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty server URL, got nil")
	}
	if !errors.Is(err, ErrInvalidServerURL) {
		t.Fatalf("expected ErrInvalidServerURL, got: %v", err)
	}
}

// --- ListByGroup ---

func TestMemoryShareStore_ListByGroup_Found(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	entries := []*ShareEntry{
		{
			ServerURL:  "https://server-a.com",
			GroupID:    "group-1",
			ShareIndex: 1,
			ShareData:  []byte("share-1"),
		},
		{
			ServerURL:  "https://server-b.com",
			GroupID:    "group-1",
			ShareIndex: 2,
			ShareData:  []byte("share-2"),
		},
		{
			ServerURL:  "https://server-a.com",
			GroupID:    "group-2",
			ShareIndex: 1,
			ShareData:  []byte("share-3"),
		},
	}

	for _, e := range entries {
		if err := store.Save(ctx, e); err != nil {
			t.Fatalf("failed to save: %v", err)
		}
	}

	result, err := store.ListByGroup(ctx, "group-1")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 entries for group-1, got %d", len(result))
	}
	for _, e := range result {
		if e.GroupID != "group-1" {
			t.Fatalf("expected group ID group-1, got %q", e.GroupID)
		}
	}
}

func TestMemoryShareStore_ListByGroup_NotFound(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	entry := newTestMemoryEntry()
	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	result, err := store.ListByGroup(ctx, "nonexistent-group")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(result))
	}
}

func TestMemoryShareStore_ListByGroup_EmptyGroupID(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	_, err := store.ListByGroup(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty group ID, got nil")
	}
	if !errors.Is(err, ErrInvalidGroupID) {
		t.Fatalf("expected ErrInvalidGroupID, got: %v", err)
	}
}

// --- MultipleSharesPerGroup ---

func TestMemoryShareStore_MultipleSharesPerGroup(t *testing.T) {
	store := newTestMemoryStore()
	ctx := context.Background()

	// Save multiple shares for the same server+group with different indices.
	entries := []*ShareEntry{
		{
			ServerURL:  "https://xkms.example.com",
			GroupID:    "custodians-1",
			ShareIndex: 1,
			ShareData:  []byte("share-data-1"),
			Purpose:    "barrier",
		},
		{
			ServerURL:  "https://xkms.example.com",
			GroupID:    "custodians-1",
			ShareIndex: 2,
			ShareData:  []byte("share-data-2"),
			Purpose:    "barrier",
		},
		{
			ServerURL:  "https://xkms.example.com",
			GroupID:    "custodians-1",
			ShareIndex: 3,
			ShareData:  []byte("share-data-3"),
			Purpose:    "barrier",
		},
	}

	for _, e := range entries {
		if err := store.Save(ctx, e); err != nil {
			t.Fatalf("failed to save share index %d: %v", e.ShareIndex, err)
		}
	}

	// Verify each share can be loaded individually by its index.
	for _, e := range entries {
		loaded, err := store.Load(ctx, e.ServerURL, e.GroupID, e.ShareIndex)
		if err != nil {
			t.Fatalf("failed to load share index %d: %v", e.ShareIndex, err)
		}
		if string(loaded.ShareData) != string(e.ShareData) {
			t.Fatalf("share index %d: expected data %q, got %q", e.ShareIndex, e.ShareData, loaded.ShareData)
		}
	}

	// Verify ListByGroup returns all shares for the group.
	grouped, err := store.ListByGroup(ctx, "custodians-1")
	if err != nil {
		t.Fatalf("failed to list by group: %v", err)
	}
	if len(grouped) != 3 {
		t.Fatalf("expected 3 shares for group, got %d", len(grouped))
	}

	// Delete one share and verify the others remain.
	if err := store.Delete(ctx, "https://xkms.example.com", "custodians-1", 2); err != nil {
		t.Fatalf("failed to delete share index 2: %v", err)
	}

	grouped, err = store.ListByGroup(ctx, "custodians-1")
	if err != nil {
		t.Fatalf("failed to list by group after delete: %v", err)
	}
	if len(grouped) != 2 {
		t.Fatalf("expected 2 shares after delete, got %d", len(grouped))
	}
}

// --- Close ---

func TestMemoryShareStore_Close(t *testing.T) {
	store := newTestMemoryStore()

	if err := store.Close(); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	ctx := context.Background()
	err := store.Save(ctx, newTestMemoryEntry())
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed after close, got: %v", err)
	}
}

func TestMemoryShareStore_Close_Idempotent(t *testing.T) {
	store := newTestMemoryStore()

	if err := store.Close(); err != nil {
		t.Fatalf("first close: expected nil error, got: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second close: expected nil error, got: %v", err)
	}
}
