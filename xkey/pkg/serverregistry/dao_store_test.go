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

package serverregistry

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

func newTestDAOStore(t *testing.T) *DAOStore {
	t.Helper()
	backend := storage.NewMemory()
	kvStore, err := kvadapter.New(backend)
	if err != nil {
		t.Fatalf("failed to create kvstore adapter: %v", err)
	}
	store, err := NewDAOStore(kvStore)
	if err != nil {
		t.Fatalf("failed to create DAO store: %v", err)
	}
	return store
}

func newTestServerEntry(url, name, protocol string) *ServerEntry {
	return &ServerEntry{
		URL:           url,
		Name:          name,
		CAFingerprint: "sha256:abc123",
		Protocol:      protocol,
	}
}

// --- NewDAOStore ---

func TestDAOStore_NewDAOStore_NilKVStore(t *testing.T) {
	store, err := NewDAOStore(nil)
	if err == nil {
		t.Fatal("expected error for nil kvstore, got nil")
	}
	if !errors.Is(err, ErrNilKVStore) {
		t.Fatalf("expected ErrNilKVStore, got: %v", err)
	}
	if store != nil {
		t.Fatal("expected nil store")
	}
}

func TestDAOStore_NewDAOStore_Success(t *testing.T) {
	store := newTestDAOStore(t)
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

// --- Register + Lookup ---

func TestDAOStore_RegisterLookup(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	entry := newTestServerEntry("https://xkms.example.com:8443", "Production", ProtocolREST)

	if err := store.Register(ctx, entry); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	// Verify RegisteredAt was set.
	if entry.RegisteredAt.IsZero() {
		t.Fatal("expected RegisteredAt to be set")
	}

	looked, err := store.Lookup(ctx, "https://xkms.example.com:8443")
	if err != nil {
		t.Fatalf("expected nil error on lookup, got: %v", err)
	}

	if looked.URL != entry.URL {
		t.Fatalf("expected URL %q, got %q", entry.URL, looked.URL)
	}
	if looked.Name != entry.Name {
		t.Fatalf("expected Name %q, got %q", entry.Name, looked.Name)
	}
	if looked.CAFingerprint != entry.CAFingerprint {
		t.Fatalf("expected CAFingerprint %q, got %q", entry.CAFingerprint, looked.CAFingerprint)
	}
	if looked.Protocol != entry.Protocol {
		t.Fatalf("expected Protocol %q, got %q", entry.Protocol, looked.Protocol)
	}
}

func TestDAOStore_Register_NilEntry(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	err := store.Register(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil entry, got nil")
	}
	if !errors.Is(err, ErrNilEntry) {
		t.Fatalf("expected ErrNilEntry, got: %v", err)
	}
}

func TestDAOStore_Register_InvalidURL(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	entry := &ServerEntry{URL: "", Name: "bad"}
	err := store.Register(ctx, entry)
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
	if !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("expected ErrInvalidURL, got: %v", err)
	}
}

func TestDAOStore_Register_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	if err := store.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	err := store.Register(ctx, newTestServerEntry("https://example.com", "test", ProtocolREST))
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got: %v", err)
	}
}

// --- DuplicateURL ---

func TestDAOStore_DuplicateURL(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	entry := newTestServerEntry("https://xkms.example.com:8443", "First", ProtocolREST)
	if err := store.Register(ctx, entry); err != nil {
		t.Fatalf("expected nil error on first register, got: %v", err)
	}

	// Second registration with same URL should fail.
	entry2 := newTestServerEntry("https://xkms.example.com:8443", "Second", ProtocolGRPC)
	err := store.Register(ctx, entry2)
	if err == nil {
		t.Fatal("expected error for duplicate URL, got nil")
	}
	if !errors.Is(err, ErrServerExists) {
		t.Fatalf("expected ErrServerExists, got: %v", err)
	}
}

// --- NotFound ---

func TestDAOStore_NotFound(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	_, err := store.Lookup(ctx, "https://nonexistent.example.com")
	if err == nil {
		t.Fatal("expected error for non-existent server, got nil")
	}
	if !errors.Is(err, ErrServerNotFound) {
		t.Fatalf("expected ErrServerNotFound, got: %v", err)
	}
}

func TestDAOStore_Lookup_EmptyURL(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	_, err := store.Lookup(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty URL, got nil")
	}
	if !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("expected ErrInvalidURL, got: %v", err)
	}
}

func TestDAOStore_Lookup_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	if err := store.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	_, err := store.Lookup(ctx, "https://example.com")
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got: %v", err)
	}
}

// --- Delete ---

func TestDAOStore_Delete(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	entry := newTestServerEntry("https://xkms.example.com:8443", "ToDelete", ProtocolGRPC)
	if err := store.Register(ctx, entry); err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	if err := store.Delete(ctx, "https://xkms.example.com:8443"); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	// Verify it is gone.
	_, err := store.Lookup(ctx, "https://xkms.example.com:8443")
	if !errors.Is(err, ErrServerNotFound) {
		t.Fatalf("expected ErrServerNotFound after delete, got: %v", err)
	}
}

func TestDAOStore_Delete_NotFound(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	err := store.Delete(ctx, "https://nonexistent.example.com")
	if err == nil {
		t.Fatal("expected error for non-existent server, got nil")
	}
	if !errors.Is(err, ErrServerNotFound) {
		t.Fatalf("expected ErrServerNotFound, got: %v", err)
	}
}

func TestDAOStore_Delete_EmptyURL(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	err := store.Delete(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty URL, got nil")
	}
	if !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("expected ErrInvalidURL, got: %v", err)
	}
}

func TestDAOStore_Delete_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	if err := store.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	err := store.Delete(ctx, "https://example.com")
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got: %v", err)
	}
}

// --- List ---

func TestDAOStore_List(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	entries := []*ServerEntry{
		newTestServerEntry("https://server-b.example.com", "Server B", ProtocolGRPC),
		newTestServerEntry("https://server-a.example.com", "Server A", ProtocolREST),
		newTestServerEntry("https://server-c.example.com", "Server C", ProtocolQUIC),
	}

	for _, e := range entries {
		if err := store.Register(ctx, e); err != nil {
			t.Fatalf("failed to register %q: %v", e.URL, err)
		}
	}

	result, err := store.List(ctx)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(result))
	}

	// Verify sorted by URL.
	for i := 0; i < len(result)-1; i++ {
		if result[i].URL >= result[i+1].URL {
			t.Fatalf("entries not sorted: %q >= %q", result[i].URL, result[i+1].URL)
		}
	}
}

func TestDAOStore_List_Empty(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	result, err := store.List(ctx)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(result))
	}
}

func TestDAOStore_List_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	if err := store.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	_, err := store.List(ctx)
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got: %v", err)
	}
}

// --- Page ---

func TestDAOStore_Page(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	// Register 5 entries.
	for i := 0; i < 5; i++ {
		entry := newTestServerEntry(
			"https://server-"+string(rune('a'+i))+".example.com",
			"Server "+string(rune('A'+i)),
			ProtocolREST,
		)
		if err := store.Register(ctx, entry); err != nil {
			t.Fatalf("failed to register entry %d: %v", i, err)
		}
	}

	// Page with size 2.
	result, err := store.Page(ctx, dao.PageQuery{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(result.Entities) != 2 {
		t.Fatalf("expected 2 entities on page 1, got %d", len(result.Entities))
	}
	if result.Total != 5 {
		t.Fatalf("expected total 5, got %d", result.Total)
	}
	if !result.HasMore {
		t.Fatal("expected HasMore to be true")
	}

	// Page 3 with size 2 should have 1 entry.
	result, err = store.Page(ctx, dao.PageQuery{Page: 3, PageSize: 2})
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(result.Entities) != 1 {
		t.Fatalf("expected 1 entity on page 3, got %d", len(result.Entities))
	}
	if result.HasMore {
		t.Fatal("expected HasMore to be false on last page")
	}
}

func TestDAOStore_Page_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	if err := store.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	_, err := store.Page(ctx, dao.PageQuery{Page: 1, PageSize: 10})
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got: %v", err)
	}
}

// --- Update ---

func TestDAOStore_Update(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	entry := newTestServerEntry("https://xkms.example.com:8443", "Original", ProtocolREST)
	if err := store.Register(ctx, entry); err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	// Update with new name and protocol.
	updated := &ServerEntry{
		URL:           "https://xkms.example.com:8443",
		Name:          "Updated",
		CAFingerprint: "sha256:updated",
		Protocol:      ProtocolGRPC,
	}
	if err := store.Update(ctx, updated); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	looked, err := store.Lookup(ctx, "https://xkms.example.com:8443")
	if err != nil {
		t.Fatalf("expected nil error on lookup, got: %v", err)
	}
	if looked.Name != "Updated" {
		t.Fatalf("expected Name %q, got %q", "Updated", looked.Name)
	}
	if looked.CAFingerprint != "sha256:updated" {
		t.Fatalf("expected CAFingerprint %q, got %q", "sha256:updated", looked.CAFingerprint)
	}
	if looked.Protocol != ProtocolGRPC {
		t.Fatalf("expected Protocol %q, got %q", ProtocolGRPC, looked.Protocol)
	}
	if looked.LastConnectedAt.IsZero() {
		t.Fatal("expected LastConnectedAt to be set after update")
	}
	// RegisteredAt should be preserved from the original.
	if looked.RegisteredAt.IsZero() {
		t.Fatal("expected RegisteredAt to be preserved from original registration")
	}
}

func TestDAOStore_Update_NotFound(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	entry := newTestServerEntry("https://nonexistent.example.com", "Ghost", ProtocolREST)
	err := store.Update(ctx, entry)
	if err == nil {
		t.Fatal("expected error for non-existent server, got nil")
	}
	if !errors.Is(err, ErrServerNotFound) {
		t.Fatalf("expected ErrServerNotFound, got: %v", err)
	}
}

func TestDAOStore_Update_NilEntry(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	err := store.Update(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil entry, got nil")
	}
	if !errors.Is(err, ErrNilEntry) {
		t.Fatalf("expected ErrNilEntry, got: %v", err)
	}
}

func TestDAOStore_Update_InvalidURL(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	entry := &ServerEntry{URL: ""}
	err := store.Update(ctx, entry)
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
	if !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("expected ErrInvalidURL, got: %v", err)
	}
}

func TestDAOStore_Update_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	if err := store.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	entry := newTestServerEntry("https://example.com", "test", ProtocolREST)
	err := store.Update(ctx, entry)
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got: %v", err)
	}
}

// --- Close ---

func TestDAOStore_Close_Idempotent(t *testing.T) {
	store := newTestDAOStore(t)

	if err := store.Close(); err != nil {
		t.Fatalf("first close: expected nil error, got: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second close: expected nil error, got: %v", err)
	}
}
