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

// errFaultInjected is a sentinel error returned by faultyBackend to simulate
// a storage fault unrelated to any "not found" condition.
var errFaultInjected = errors.New("sharestore: injected storage fault")

// faultyBackend wraps a real storage.Backend and injects failures on
// selected operations, letting tests exercise the raw-error propagation
// paths in backendShareStore without a mock framework.
type faultyBackend struct {
	storage.Backend
	failExists bool
	failGet    bool
	failScan   bool
}

func (f *faultyBackend) Exists(ctx context.Context, key string) (bool, error) {
	if f.failExists {
		return false, errFaultInjected
	}
	return f.Backend.Exists(ctx, key)
}

func (f *faultyBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if f.failGet {
		return nil, errFaultInjected
	}
	return f.Backend.Get(ctx, key)
}

func (f *faultyBackend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	if f.failScan {
		return errFaultInjected
	}
	return f.Backend.Scan(ctx, prefix, fn)
}

// TestBackendShareStore_Save_ExistsError verifies Save propagates a raw
// backend error from the existence check, rather than swallowing it or
// misreporting ErrShareExists.
func TestBackendShareStore_Save_ExistsError(t *testing.T) {
	backend := &faultyBackend{Backend: storage.NewMemory(), failExists: true}
	store, err := NewBackendShareStore(backend, "shamir/")
	if err != nil {
		t.Fatalf("NewBackendShareStore: %v", err)
	}

	err = store.Save(context.Background(), sampleEntry())
	if !errors.Is(err, errFaultInjected) {
		t.Fatalf("Save() = %v, want errFaultInjected", err)
	}
}

// TestBackendShareStore_Save_MarshalError verifies Save propagates a JSON
// marshal error. time.Time.MarshalJSON genuinely fails for years outside
// [0, 9999], giving a real (not synthetic) marshal failure.
func TestBackendShareStore_Save_MarshalError(t *testing.T) {
	store, err := NewBackendShareStore(storage.NewMemory(), "shamir/")
	if err != nil {
		t.Fatalf("NewBackendShareStore: %v", err)
	}

	entry := sampleEntry()
	entry.ReceivedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)

	err = store.Save(context.Background(), entry)
	if err == nil {
		t.Fatal("Save() = nil, want marshal error")
	}
	if errors.Is(err, ErrShareExists) {
		t.Fatalf("Save() = %v, want a marshal error not ErrShareExists", err)
	}
}

// TestBackendShareStore_Load_GetError verifies Load propagates a raw backend
// error, rather than translating it to ErrShareNotFound, when the failure is
// unrelated to a missing key.
func TestBackendShareStore_Load_GetError(t *testing.T) {
	backend := &faultyBackend{Backend: storage.NewMemory()}
	store, err := NewBackendShareStore(backend, "shamir/")
	if err != nil {
		t.Fatalf("NewBackendShareStore: %v", err)
	}

	entry := sampleEntry()
	if err := store.Save(context.Background(), entry); err != nil {
		t.Fatalf("Save: %v", err)
	}

	backend.failGet = true
	loaded, err := store.Load(context.Background(), entry.ServerURL, entry.GroupID, entry.ShareIndex)
	if !errors.Is(err, errFaultInjected) {
		t.Fatalf("Load() err = %v, want errFaultInjected", err)
	}
	if loaded != nil {
		t.Fatalf("Load() entry = %+v, want nil", loaded)
	}
}

// TestBackendShareStore_Load_UnmarshalError verifies Load surfaces a JSON
// decode error when the persisted value is corrupt.
func TestBackendShareStore_Load_UnmarshalError(t *testing.T) {
	backend := storage.NewMemory()
	store, err := NewBackendShareStore(backend, "shamir/")
	if err != nil {
		t.Fatalf("NewBackendShareStore: %v", err)
	}
	bss := store.(*backendShareStore)

	k := bss.key("https://xkms.example.com", "group-1", 1)
	if err := backend.Put(context.Background(), k, []byte("not-json")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	loaded, err := store.Load(context.Background(), "https://xkms.example.com", "group-1", 1)
	if err == nil {
		t.Fatal("Load() = nil error, want unmarshal error")
	}
	if errors.Is(err, ErrShareNotFound) {
		t.Fatalf("Load() = %v, want a decode error not ErrShareNotFound", err)
	}
	if loaded != nil {
		t.Fatalf("Load() entry = %+v, want nil", loaded)
	}
}

// TestBackendShareStore_List_ScanError verifies List propagates a raw
// backend error encountered while scanning.
func TestBackendShareStore_List_ScanError(t *testing.T) {
	backend := &faultyBackend{Backend: storage.NewMemory(), failScan: true}
	store, err := NewBackendShareStore(backend, "shamir/")
	if err != nil {
		t.Fatalf("NewBackendShareStore: %v", err)
	}

	entries, err := store.List(context.Background())
	if !errors.Is(err, errFaultInjected) {
		t.Fatalf("List() err = %v, want errFaultInjected", err)
	}
	if entries != nil {
		t.Fatalf("List() entries = %+v, want nil", entries)
	}
}

// TestBackendShareStore_List_UnmarshalError verifies List surfaces a JSON
// decode error when a scanned value is corrupt.
func TestBackendShareStore_List_UnmarshalError(t *testing.T) {
	backend := storage.NewMemory()
	store, err := NewBackendShareStore(backend, "shamir/")
	if err != nil {
		t.Fatalf("NewBackendShareStore: %v", err)
	}
	bss := store.(*backendShareStore)

	k := bss.key("https://xkms.example.com", "group-1", 1)
	if err := backend.Put(context.Background(), k, []byte("not-json")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	entries, err := store.List(context.Background())
	if err == nil {
		t.Fatal("List() = nil error, want unmarshal error")
	}
	if entries != nil {
		t.Fatalf("List() entries = %+v, want nil", entries)
	}
}

// TestBackendShareStore_Delete_ExistsError verifies Delete propagates a raw
// backend error from the existence check, rather than misreporting
// ErrShareNotFound.
func TestBackendShareStore_Delete_ExistsError(t *testing.T) {
	backend := &faultyBackend{Backend: storage.NewMemory(), failExists: true}
	store, err := NewBackendShareStore(backend, "shamir/")
	if err != nil {
		t.Fatalf("NewBackendShareStore: %v", err)
	}

	err = store.Delete(context.Background(), "https://xkms.example.com", "group-1", 1)
	if !errors.Is(err, errFaultInjected) {
		t.Fatalf("Delete() = %v, want errFaultInjected", err)
	}
}

// TestMemoryShareStore_List_MultipleGroups verifies entries from distinct
// groups are ordered by GroupID before ShareIndex, exercising the
// group-inequality branch of the sort comparator.
func TestMemoryShareStore_List_MultipleGroups(t *testing.T) {
	store := NewMemoryShareStore()
	ctx := context.Background()

	entryB := sampleEntry()
	entryB.GroupID = "group-b"
	entryB.ShareIndex = 1
	if err := store.Save(ctx, entryB); err != nil {
		t.Fatalf("Save entryB: %v", err)
	}

	entryA := sampleEntry()
	entryA.GroupID = "group-a"
	entryA.ShareIndex = 5
	if err := store.Save(ctx, entryA); err != nil {
		t.Fatalf("Save entryA: %v", err)
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List len = %d, want 2", len(list))
	}
	if list[0].GroupID != "group-a" || list[1].GroupID != "group-b" {
		t.Fatalf("List not ordered by group: %s, %s", list[0].GroupID, list[1].GroupID)
	}
}

// TestBackendShareStore_List_MultipleGroups verifies entries from distinct
// groups are ordered by GroupID before ShareIndex, exercising the
// group-inequality branch of backendShareStore's sort comparator.
func TestBackendShareStore_List_MultipleGroups(t *testing.T) {
	store, err := NewBackendShareStore(storage.NewMemory(), "shamir/")
	if err != nil {
		t.Fatalf("NewBackendShareStore: %v", err)
	}
	ctx := context.Background()

	entryB := sampleEntry()
	entryB.GroupID = "group-b"
	entryB.ShareIndex = 1
	if err := store.Save(ctx, entryB); err != nil {
		t.Fatalf("Save entryB: %v", err)
	}

	entryA := sampleEntry()
	entryA.GroupID = "group-a"
	entryA.ShareIndex = 5
	if err := store.Save(ctx, entryA); err != nil {
		t.Fatalf("Save entryA: %v", err)
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List len = %d, want 2", len(list))
	}
	if list[0].GroupID != "group-a" || list[1].GroupID != "group-b" {
		t.Fatalf("List not ordered by group: %s, %s", list[0].GroupID, list[1].GroupID)
	}
}
