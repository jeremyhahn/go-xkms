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

func newTestBackendStore(t *testing.T) *BackendShareStore {
	t.Helper()
	backend := storage.NewMemory()
	store, err := NewBackendShareStore(backend, "shares/")
	if err != nil {
		t.Fatalf("failed to create backend store: %v", err)
	}
	return store
}

func newTestEntry() *ShareEntry {
	return &ShareEntry{
		ServerURL:  "https://xkms.example.com",
		GroupID:    "custodians-1",
		GroupName:  "Primary Custodians",
		ShareIndex: 1,
		ShareData:  []byte("secret-share-data"),
		Purpose:    "barrier",
	}
}

// --- NewBackendShareStore ---

func TestNewBackendShareStore_Success(t *testing.T) {
	backend := storage.NewMemory()
	store, err := NewBackendShareStore(backend, "shares/")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestNewBackendShareStore_NilBackend(t *testing.T) {
	store, err := NewBackendShareStore(nil, "shares/")
	if err == nil {
		t.Fatal("expected error for nil backend, got nil")
	}
	if !errors.Is(err, ErrNilBackend) {
		t.Fatalf("expected ErrNilBackend, got: %v", err)
	}
	if store != nil {
		t.Fatal("expected nil store")
	}
}

// --- Save ---

func TestBackendShareStore_Save_Success(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()
	entry := newTestEntry()

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	// Verify ReceivedAt was set.
	if entry.ReceivedAt.IsZero() {
		t.Fatal("expected ReceivedAt to be set")
	}
}

func TestBackendShareStore_Save_PreservesReceivedAt(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()
	entry := newTestEntry()
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

func TestBackendShareStore_Save_NilEntry(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()

	err := store.Save(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil entry, got nil")
	}
	if !errors.Is(err, ErrNilEntry) {
		t.Fatalf("expected ErrNilEntry, got: %v", err)
	}
}

func TestBackendShareStore_Save_InvalidEntry(t *testing.T) {
	store := newTestBackendStore(t)
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

func TestBackendShareStore_Save_Duplicate(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()
	entry := newTestEntry()

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("expected nil error on first save, got: %v", err)
	}

	// Second save with same server+group+shareIndex should fail.
	entry2 := newTestEntry()
	err := store.Save(ctx, entry2)
	if err == nil {
		t.Fatal("expected error for duplicate entry, got nil")
	}
	if !errors.Is(err, ErrShareExists) {
		t.Fatalf("expected ErrShareExists, got: %v", err)
	}
}

func TestBackendShareStore_Save_Closed(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()

	if err := store.Close(); err != nil {
		t.Fatalf("failed to close store: %v", err)
	}

	err := store.Save(ctx, newTestEntry())
	if err == nil {
		t.Fatal("expected error on closed store, got nil")
	}
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got: %v", err)
	}
}

// --- Load ---

func TestBackendShareStore_Load_Success(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()
	entry := newTestEntry()

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
	if string(loaded.ShareData) != string(entry.ShareData) {
		t.Fatalf("expected share data %q, got %q", entry.ShareData, loaded.ShareData)
	}
	if loaded.Purpose != entry.Purpose {
		t.Fatalf("expected purpose %q, got %q", entry.Purpose, loaded.Purpose)
	}
}

func TestBackendShareStore_Load_NotFound(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()

	_, err := store.Load(ctx, "https://nonexistent.com", "group-1", 1)
	if err == nil {
		t.Fatal("expected error for non-existent share, got nil")
	}
	if !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("expected ErrShareNotFound, got: %v", err)
	}
}

func TestBackendShareStore_Load_EmptyServerURL(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()

	_, err := store.Load(ctx, "", "group-1", 1)
	if err == nil {
		t.Fatal("expected error for empty server URL, got nil")
	}
	if !errors.Is(err, ErrInvalidServerURL) {
		t.Fatalf("expected ErrInvalidServerURL, got: %v", err)
	}
}

func TestBackendShareStore_Load_EmptyGroupID(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()

	_, err := store.Load(ctx, "https://xkms.example.com", "", 1)
	if err == nil {
		t.Fatal("expected error for empty group ID, got nil")
	}
	if !errors.Is(err, ErrInvalidGroupID) {
		t.Fatalf("expected ErrInvalidGroupID, got: %v", err)
	}
}

func TestBackendShareStore_Load_Closed(t *testing.T) {
	store := newTestBackendStore(t)
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

func TestBackendShareStore_Delete_Success(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()
	entry := newTestEntry()

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	if err := store.Delete(ctx, entry.ServerURL, entry.GroupID, entry.ShareIndex); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	// Verify it's gone.
	_, err := store.Load(ctx, entry.ServerURL, entry.GroupID, entry.ShareIndex)
	if !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("expected ErrShareNotFound after delete, got: %v", err)
	}
}

func TestBackendShareStore_Delete_NotFound(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()

	err := store.Delete(ctx, "https://nonexistent.com", "group-1", 1)
	if err == nil {
		t.Fatal("expected error for non-existent share, got nil")
	}
	if !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("expected ErrShareNotFound, got: %v", err)
	}
}

func TestBackendShareStore_Delete_EmptyServerURL(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()

	err := store.Delete(ctx, "", "group-1", 1)
	if err == nil {
		t.Fatal("expected error for empty server URL, got nil")
	}
	if !errors.Is(err, ErrInvalidServerURL) {
		t.Fatalf("expected ErrInvalidServerURL, got: %v", err)
	}
}

func TestBackendShareStore_Delete_EmptyGroupID(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()

	err := store.Delete(ctx, "https://xkms.example.com", "", 1)
	if err == nil {
		t.Fatal("expected error for empty group ID, got nil")
	}
	if !errors.Is(err, ErrInvalidGroupID) {
		t.Fatalf("expected ErrInvalidGroupID, got: %v", err)
	}
}

func TestBackendShareStore_Delete_Closed(t *testing.T) {
	store := newTestBackendStore(t)
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

func TestBackendShareStore_List_Empty(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()

	entries, err := store.List(ctx)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestBackendShareStore_List_MultipleSorted(t *testing.T) {
	store := newTestBackendStore(t)
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

	// Verify sorted order by Key().
	for i := 0; i < len(result)-1; i++ {
		if result[i].Key() >= result[i+1].Key() {
			t.Fatalf("entries not sorted: %q >= %q", result[i].Key(), result[i+1].Key())
		}
	}
}

func TestBackendShareStore_List_Closed(t *testing.T) {
	store := newTestBackendStore(t)
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

func TestBackendShareStore_ListByServer_Found(t *testing.T) {
	store := newTestBackendStore(t)
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
	for _, entry := range result {
		if entry.ServerURL != "https://server-a.com" {
			t.Fatalf("expected server URL https://server-a.com, got %q", entry.ServerURL)
		}
	}
}

func TestBackendShareStore_ListByServer_NotFound(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()

	entry := newTestEntry()
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

func TestBackendShareStore_ListByServer_EmptyServerURL(t *testing.T) {
	store := newTestBackendStore(t)
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

func TestBackendShareStore_ListByGroup_Found(t *testing.T) {
	store := newTestBackendStore(t)
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

func TestBackendShareStore_ListByGroup_NotFound(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()

	entry := newTestEntry()
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

func TestBackendShareStore_ListByGroup_EmptyGroupID(t *testing.T) {
	store := newTestBackendStore(t)
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

func TestBackendShareStore_MultipleSharesPerGroup(t *testing.T) {
	store := newTestBackendStore(t)
	ctx := context.Background()

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

	for _, e := range entries {
		loaded, err := store.Load(ctx, e.ServerURL, e.GroupID, e.ShareIndex)
		if err != nil {
			t.Fatalf("failed to load share index %d: %v", e.ShareIndex, err)
		}
		if string(loaded.ShareData) != string(e.ShareData) {
			t.Fatalf("share index %d: expected data %q, got %q", e.ShareIndex, e.ShareData, loaded.ShareData)
		}
	}

	grouped, err := store.ListByGroup(ctx, "custodians-1")
	if err != nil {
		t.Fatalf("failed to list by group: %v", err)
	}
	if len(grouped) != 3 {
		t.Fatalf("expected 3 shares for group, got %d", len(grouped))
	}

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

func TestBackendShareStore_Close(t *testing.T) {
	store := newTestBackendStore(t)

	if err := store.Close(); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	// Verify subsequent operations fail.
	ctx := context.Background()
	err := store.Save(ctx, newTestEntry())
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed after close, got: %v", err)
	}
}

func TestBackendShareStore_Close_Idempotent(t *testing.T) {
	store := newTestBackendStore(t)

	if err := store.Close(); err != nil {
		t.Fatalf("first close: expected nil error, got: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second close: expected nil error, got: %v", err)
	}
}
