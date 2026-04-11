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

package agent

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	dberrors "github.com/jeremyhahn/go-qrdb/pkg/errors"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
)

// testKVStore is a minimal in-memory KVStore for unit testing.
// Index operations are no-ops; the DAOStore falls back to scan.
type testKVStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newTestKVStore() kvstore.KVStore {
	return &testKVStore{data: make(map[string][]byte)}
}

func (m *testKVStore) Put(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[key] = cp
	return nil
}

func (m *testKVStore) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[key]
	if !ok {
		return nil, &dberrors.QRDBError{Code: dberrors.ErrNotFound, Op: "kv.get"}
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (m *testKVStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *testKVStore) Scan(_ context.Context, prefix string, fn func(string, []byte) error) error {
	m.mu.RLock()
	var keys []string
	for k := range m.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k)
		}
	}
	values := make(map[string][]byte, len(keys))
	for _, k := range keys {
		v := m.data[k]
		cp := make([]byte, len(v))
		copy(cp, v)
		values[k] = cp
	}
	m.mu.RUnlock()
	sort.Strings(keys)
	for _, k := range keys {
		if err := fn(k, values[k]); err != nil {
			return err
		}
	}
	return nil
}

func (m *testKVStore) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for k := range m.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (m *testKVStore) Exists(_ context.Context, key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.data[key]
	return ok, nil
}

func (m *testKVStore) RegisterEntityIndexes(_ string, _ []kvstore.EntityIndex) error { return nil }

func (m *testKVStore) QueryIndex(_ context.Context, _ string, _ []byte) ([][]byte, error) {
	return nil, nil
}

func (m *testKVStore) ScanIndex(_ context.Context, _ string, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

var _ kvstore.KVStore = (*testKVStore)(nil)

// newTestDAOStore creates a DAOStore with an in-memory KVStore for testing.
func newTestDAOStore(t *testing.T) *DAOStore {
	t.Helper()
	store, err := NewDAOStore(newTestKVStore())
	if err != nil {
		t.Fatalf("NewDAOStore() error: %v", err)
	}
	return store
}

func testAgentInfo(id, name string) *AgentInfo {
	now := time.Now().UTC().Truncate(time.Second)
	return &AgentInfo{
		ID:                     id,
		Name:                   name,
		Address:                "10.0.0.1:9443",
		CertificateFingerprint: "fp-" + id,
		Status:                 "active",
		EnrolledAt:             now,
		LastSeen:               now,
	}
}

// --- Constructor tests ---

func TestDAOStore_NewDAOStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store, err := NewDAOStore(newTestKVStore())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if store == nil {
			t.Fatal("expected non-nil store")
		}
	})

	t.Run("NilKVStore", func(t *testing.T) {
		store, err := NewDAOStore(nil)
		if err == nil {
			t.Fatal("expected error for nil kvstore")
		}
		if store != nil {
			t.Fatal("expected nil store")
		}
		if err != ErrNilKVStore {
			t.Fatalf("expected ErrNilKVStore, got: %v", err)
		}
	})
}

// --- SaveAgent + GetAgent round-trip ---

func TestDAOStore_SaveGet(t *testing.T) {
	t.Run("SaveAndRetrieve", func(t *testing.T) {
		store := newTestDAOStore(t)
		agent := testAgentInfo("device-001", "test-agent")

		if err := store.SaveAgent(agent); err != nil {
			t.Fatalf("SaveAgent() error: %v", err)
		}

		got, err := store.GetAgent("device-001")
		if err != nil {
			t.Fatalf("GetAgent() error: %v", err)
		}

		if got.ID != agent.ID {
			t.Errorf("ID = %q, want %q", got.ID, agent.ID)
		}
		if got.Name != agent.Name {
			t.Errorf("Name = %q, want %q", got.Name, agent.Name)
		}
		if got.Address != agent.Address {
			t.Errorf("Address = %q, want %q", got.Address, agent.Address)
		}
		if got.CertificateFingerprint != agent.CertificateFingerprint {
			t.Errorf("CertificateFingerprint = %q, want %q", got.CertificateFingerprint, agent.CertificateFingerprint)
		}
		if got.Status != agent.Status {
			t.Errorf("Status = %q, want %q", got.Status, agent.Status)
		}
	})

	t.Run("SaveNilAgent", func(t *testing.T) {
		store := newTestDAOStore(t)
		if err := store.SaveAgent(nil); err == nil {
			t.Fatal("expected error for nil agent")
		}
	})

	t.Run("SaveEmptyID", func(t *testing.T) {
		store := newTestDAOStore(t)
		agent := &AgentInfo{ID: ""}
		if err := store.SaveAgent(agent); err == nil {
			t.Fatal("expected error for empty agent ID")
		}
	})
}

// --- DeleteAgent ---

func TestDAOStore_Delete(t *testing.T) {
	t.Run("SaveThenDelete", func(t *testing.T) {
		store := newTestDAOStore(t)
		agent := testAgentInfo("device-del", "delete-me")

		if err := store.SaveAgent(agent); err != nil {
			t.Fatalf("SaveAgent() error: %v", err)
		}

		if err := store.DeleteAgent("device-del"); err != nil {
			t.Fatalf("DeleteAgent() error: %v", err)
		}

		// Verify it's gone.
		_, err := store.GetAgent("device-del")
		if err == nil {
			t.Fatal("expected error after delete")
		}
		if err != ErrAgentNotFound {
			t.Fatalf("expected ErrAgentNotFound, got: %v", err)
		}
	})

	t.Run("DeleteEmptyID", func(t *testing.T) {
		store := newTestDAOStore(t)
		if err := store.DeleteAgent(""); err == nil {
			t.Fatal("expected error for empty ID")
		}
	})

	t.Run("DeleteNonExistent", func(t *testing.T) {
		store := newTestDAOStore(t)
		err := store.DeleteAgent("no-such-device")
		if err == nil {
			t.Fatal("expected error for non-existent device")
		}
		if err != ErrAgentNotFound {
			t.Fatalf("expected ErrAgentNotFound, got: %v", err)
		}
	})
}

// --- ListAgents ---

func TestDAOStore_List(t *testing.T) {
	t.Run("ListMultiple", func(t *testing.T) {
		store := newTestDAOStore(t)

		agents := []*AgentInfo{
			testAgentInfo("device-a", "agent-a"),
			testAgentInfo("device-b", "agent-b"),
			testAgentInfo("device-c", "agent-c"),
		}
		for _, a := range agents {
			if err := store.SaveAgent(a); err != nil {
				t.Fatalf("SaveAgent(%s) error: %v", a.ID, err)
			}
		}

		list, err := store.ListAgents()
		if err != nil {
			t.Fatalf("ListAgents() error: %v", err)
		}
		if len(list) != 3 {
			t.Fatalf("ListAgents() returned %d agents, want 3", len(list))
		}

		// Verify all device IDs are present.
		ids := make(map[string]bool, len(list))
		for _, a := range list {
			ids[a.ID] = true
		}
		for _, want := range []string{"device-a", "device-b", "device-c"} {
			if !ids[want] {
				t.Errorf("missing agent %q in list", want)
			}
		}
	})

	t.Run("ListEmpty", func(t *testing.T) {
		store := newTestDAOStore(t)
		list, err := store.ListAgents()
		if err != nil {
			t.Fatalf("ListAgents() error: %v", err)
		}
		if len(list) != 0 {
			t.Fatalf("ListAgents() returned %d agents, want 0", len(list))
		}
	})
}

// --- Page ---

func TestDAOStore_Page(t *testing.T) {
	t.Run("Paginate", func(t *testing.T) {
		store := newTestDAOStore(t)

		for i := 0; i < 5; i++ {
			id := "device-" + string(rune('a'+i))
			if err := store.SaveAgent(testAgentInfo(id, "agent-"+id)); err != nil {
				t.Fatalf("SaveAgent() error: %v", err)
			}
		}

		ctx := context.Background()

		// First page of 2.
		page1, err := store.Page(ctx, dao.PageQuery{Page: 1, PageSize: 2})
		if err != nil {
			t.Fatalf("Page(1) error: %v", err)
		}
		if len(page1.Entities) != 2 {
			t.Fatalf("Page(1) returned %d entities, want 2", len(page1.Entities))
		}
		if page1.Total != 5 {
			t.Errorf("Page(1).Total = %d, want 5", page1.Total)
		}
		if !page1.HasMore {
			t.Error("Page(1).HasMore = false, want true")
		}

		// Last page.
		page3, err := store.Page(ctx, dao.PageQuery{Page: 3, PageSize: 2})
		if err != nil {
			t.Fatalf("Page(3) error: %v", err)
		}
		if len(page3.Entities) != 1 {
			t.Fatalf("Page(3) returned %d entities, want 1", len(page3.Entities))
		}
		if page3.HasMore {
			t.Error("Page(3).HasMore = true, want false")
		}
	})
}

// --- NotFound ---

func TestDAOStore_NotFound(t *testing.T) {
	t.Run("GetNonExistent", func(t *testing.T) {
		store := newTestDAOStore(t)
		_, err := store.GetAgent("non-existent-device")
		if err == nil {
			t.Fatal("expected error for non-existent agent")
		}
		if err != ErrAgentNotFound {
			t.Fatalf("expected ErrAgentNotFound, got: %v", err)
		}
	})

	t.Run("GetEmptyID", func(t *testing.T) {
		store := newTestDAOStore(t)
		_, err := store.GetAgent("")
		if err == nil {
			t.Fatal("expected error for empty ID")
		}
	})
}

// --- DuplicateDeviceID (upsert) ---

func TestDAOStore_DuplicateDeviceID(t *testing.T) {
	t.Run("UpdateExisting", func(t *testing.T) {
		store := newTestDAOStore(t)

		agent := testAgentInfo("device-dup", "original-name")
		if err := store.SaveAgent(agent); err != nil {
			t.Fatalf("SaveAgent() error: %v", err)
		}

		// Save again with updated fields.
		updated := testAgentInfo("device-dup", "updated-name")
		updated.Status = "revoked"
		if err := store.SaveAgent(updated); err != nil {
			t.Fatalf("SaveAgent(updated) error: %v", err)
		}

		// Verify the update took effect.
		got, err := store.GetAgent("device-dup")
		if err != nil {
			t.Fatalf("GetAgent() error: %v", err)
		}
		if got.Name != "updated-name" {
			t.Errorf("Name = %q, want %q", got.Name, "updated-name")
		}
		if got.Status != "revoked" {
			t.Errorf("Status = %q, want %q", got.Status, "revoked")
		}

		// Verify we still have only one agent, not two.
		list, err := store.ListAgents()
		if err != nil {
			t.Fatalf("ListAgents() error: %v", err)
		}
		if len(list) != 1 {
			t.Fatalf("ListAgents() returned %d agents, want 1 (no duplicate)", len(list))
		}
	})
}

// --- EnrollmentStore interface compliance ---

func TestDAOStore_ImplementsEnrollmentStore(t *testing.T) {
	var _ EnrollmentStore = (*DAOStore)(nil)
}
