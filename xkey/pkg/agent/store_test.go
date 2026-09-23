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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileStore_NewFileStore_Success(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store == nil {
		t.Fatal("store should not be nil")
	}
}

func TestFileStore_NewFileStore_EmptyDir(t *testing.T) {
	_, err := NewFileStore("", testLogger())
	if err == nil {
		t.Fatal("expected error for empty directory")
	}
	if !errors.Is(err, ErrStoreDir) {
		t.Errorf("expected ErrStoreDir, got %v", err)
	}
}

func TestFileStore_NewFileStore_NilLogger(t *testing.T) {
	_, err := NewFileStore(t.TempDir(), nil)
	if !errors.Is(err, ErrNilLogger) {
		t.Errorf("expected ErrNilLogger, got %v", err)
	}
}

func TestFileStore_NewFileStore_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub", "agents")
	_, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("should be a directory")
	}
}

func TestFileStore_SaveAndGet(t *testing.T) {
	store, err := NewFileStore(t.TempDir(), testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	agent := &AgentInfo{
		ID:                     "test-agent-1",
		Name:                   "Test Agent 1",
		Address:                "192.168.1.100:9443",
		CertificateFingerprint: "abc123",
		EnrolledAt:             time.Now().Truncate(time.Second),
		LastSeen:               time.Now().Truncate(time.Second),
		Status:                 "active",
	}

	if err := store.SaveAgent(agent); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	got, err := store.GetAgent("test-agent-1")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}

	if got.ID != agent.ID {
		t.Errorf("expected ID %q, got %q", agent.ID, got.ID)
	}
	if got.Name != agent.Name {
		t.Errorf("expected Name %q, got %q", agent.Name, got.Name)
	}
	if got.Address != agent.Address {
		t.Errorf("expected Address %q, got %q", agent.Address, got.Address)
	}
	if got.Status != agent.Status {
		t.Errorf("expected Status %q, got %q", agent.Status, got.Status)
	}
}

func TestFileStore_SaveAgent_NilAgent(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	err := store.SaveAgent(nil)
	if err == nil {
		t.Fatal("expected error for nil agent")
	}
}

func TestFileStore_SaveAgent_EmptyID(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	err := store.SaveAgent(&AgentInfo{ID: ""})
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestFileStore_GetAgent_EmptyID(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	_, err := store.GetAgent("")
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestFileStore_GetAgent_NotFound(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	_, err := store.GetAgent("nonexistent")
	if !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("expected ErrAgentNotFound, got %v", err)
	}
}

func TestFileStore_ListAgents_Empty(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	agents, err := store.ListAgents()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("expected empty list, got %d", len(agents))
	}
}

func TestFileStore_ListAgents_Multiple(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	for i := 0; i < 3; i++ {
		agent := &AgentInfo{
			ID:     "agent-" + string(rune('a'+i)),
			Name:   "Agent " + string(rune('A'+i)),
			Status: "active",
		}
		if err := store.SaveAgent(agent); err != nil {
			t.Fatalf("save failed: %v", err)
		}
	}

	agents, err := store.ListAgents()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(agents) != 3 {
		t.Errorf("expected 3 agents, got %d", len(agents))
	}
}

func TestFileStore_DeleteAgent_Success(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	agent := &AgentInfo{ID: "to-delete", Status: "active"}
	if err := store.SaveAgent(agent); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	if err := store.DeleteAgent("to-delete"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	_, err := store.GetAgent("to-delete")
	if !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("expected ErrAgentNotFound after delete, got %v", err)
	}
}

func TestFileStore_DeleteAgent_NotFound(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	err := store.DeleteAgent("nonexistent")
	if !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("expected ErrAgentNotFound, got %v", err)
	}
}

func TestFileStore_DeleteAgent_EmptyID(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	err := store.DeleteAgent("")
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestFileStore_SaveAgent_Overwrite(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	agent := &AgentInfo{ID: "overwrite-test", Status: "active"}
	if err := store.SaveAgent(agent); err != nil {
		t.Fatalf("first save failed: %v", err)
	}

	agent.Status = "revoked"
	if err := store.SaveAgent(agent); err != nil {
		t.Fatalf("second save failed: %v", err)
	}

	got, err := store.GetAgent("overwrite-test")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got.Status != "revoked" {
		t.Errorf("expected status 'revoked', got %q", got.Status)
	}
}

func TestFileStore_ListAgents_IgnoresNonJSON(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileStore(dir, testLogger())

	// Create a non-JSON file inside the agents/ subdirectory ListAgents
	// actually scans.
	if err := os.WriteFile(filepath.Join(dir, "agents", "readme.txt"), []byte("hello"), 0600); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create a valid agent file.
	agent := &AgentInfo{ID: "valid-agent", Status: "active"}
	if err := store.SaveAgent(agent); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	agents, err := store.ListAgents()
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(agents) != 1 {
		t.Errorf("expected 1 agent (ignoring txt file), got %d", len(agents))
	}
}

func TestFileStore_ListAgents_IgnoresMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileStore(dir, testLogger())

	// Create a malformed JSON file inside the agents/ subdirectory
	// ListAgents actually scans.
	if err := os.WriteFile(filepath.Join(dir, "agents", "bad.json"), []byte("{invalid json"), 0600); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	agents, err := store.ListAgents()
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("expected 0 agents (malformed file ignored), got %d", len(agents))
	}
}

// --- FileStore code tests ---

func TestFileStore_SaveCode_EmptyHash(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())
	if err := store.SaveCode("", time.Now().Add(time.Hour)); !errors.Is(err, ErrEnrollmentCodeInvalid) {
		t.Errorf("expected ErrEnrollmentCodeInvalid, got %v", err)
	}
}

func TestFileStore_SavePending_Nil(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())
	if err := store.SavePending(nil); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got %v", err)
	}
}

func TestFileStore_GetPending_EmptyID(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())
	if _, err := store.GetPending(""); err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestFileStore_DeletePending_EmptyID(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())
	if err := store.DeletePending(""); err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestFileStore_SaveAndConsumeCode(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	hash := "deadbeef"
	if err := store.SaveCode(hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}

	if err := store.ConsumeCode(hash); err != nil {
		t.Fatalf("ConsumeCode: %v", err)
	}
}

func TestFileStore_ConsumeCode_Invalid(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	if err := store.ConsumeCode("never-saved"); !errors.Is(err, ErrEnrollmentCodeInvalid) {
		t.Errorf("expected ErrEnrollmentCodeInvalid, got %v", err)
	}
}

func TestFileStore_ConsumeCode_Expired(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	hash := "expired-hash"
	if err := store.SaveCode(hash, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}

	if err := store.ConsumeCode(hash); !errors.Is(err, ErrEnrollmentCodeExpired) {
		t.Errorf("expected ErrEnrollmentCodeExpired, got %v", err)
	}

	// The expired code was consumed on the way out and cannot be retried.
	if err := store.ConsumeCode(hash); !errors.Is(err, ErrEnrollmentCodeInvalid) {
		t.Errorf("expected the expired code to already be gone, got %v", err)
	}
}

func TestFileStore_ConsumeCode_SingleUse(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	hash := "single-use-hash"
	if err := store.SaveCode(hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	if err := store.ConsumeCode(hash); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := store.ConsumeCode(hash); !errors.Is(err, ErrEnrollmentCodeInvalid) {
		t.Errorf("expected ErrEnrollmentCodeInvalid on reuse, got %v", err)
	}
}

func TestFileStore_CleanExpiredCodes(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	if err := store.SaveCode("expired", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	if err := store.SaveCode("valid", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}

	removed, err := store.CleanExpiredCodes()
	if err != nil {
		t.Fatalf("CleanExpiredCodes: %v", err)
	}
	if removed != 1 {
		t.Errorf("expected 1 removed code, got %d", removed)
	}

	if err := store.ConsumeCode("valid"); err != nil {
		t.Errorf("valid code should survive cleanup: %v", err)
	}
}

// --- FileStore pending tests ---

func TestFileStore_SaveAndGetPending(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	p := &PendingEnrollment{
		ID:          "req-1",
		CSR:         []byte("csr-bytes"),
		Fingerprint: "fp-1",
		RequestedAt: time.Now().Truncate(time.Second),
		Status:      "pending",
	}
	if err := store.SavePending(p); err != nil {
		t.Fatalf("SavePending: %v", err)
	}

	got, err := store.GetPending("req-1")
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if got.Fingerprint != p.Fingerprint || string(got.CSR) != string(p.CSR) {
		t.Errorf("GetPending returned %+v, want %+v", got, p)
	}
}

func TestFileStore_GetPending_NotFound(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	if _, err := store.GetPending("nonexistent"); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got %v", err)
	}
}

func TestFileStore_ListPending(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	for _, id := range []string{"r1", "r2"} {
		if err := store.SavePending(&PendingEnrollment{ID: id, Status: "pending"}); err != nil {
			t.Fatalf("SavePending(%s): %v", id, err)
		}
	}

	all, err := store.ListPending()
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 pending requests, got %d", len(all))
	}
}

func TestFileStore_DeletePending_Success(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	if err := store.SavePending(&PendingEnrollment{ID: "to-delete", Status: "pending"}); err != nil {
		t.Fatalf("SavePending: %v", err)
	}
	if err := store.DeletePending("to-delete"); err != nil {
		t.Fatalf("DeletePending: %v", err)
	}
	if _, err := store.GetPending("to-delete"); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound after delete, got %v", err)
	}
}

func TestFileStore_DeletePending_NotFound(t *testing.T) {
	store, _ := NewFileStore(t.TempDir(), testLogger())

	if err := store.DeletePending("nonexistent"); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got %v", err)
	}
}

// --- MemoryStore tests ---

func TestMemoryStore_SaveAndGet(t *testing.T) {
	store := NewMemoryStore()

	agent := &AgentInfo{
		ID:     "mem-agent-1",
		Name:   "Memory Agent",
		Status: "active",
	}

	if err := store.SaveAgent(agent); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	got, err := store.GetAgent("mem-agent-1")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got.Name != "Memory Agent" {
		t.Errorf("expected name 'Memory Agent', got %q", got.Name)
	}
}

func TestMemoryStore_SaveAgent_Nil(t *testing.T) {
	store := NewMemoryStore()
	err := store.SaveAgent(nil)
	if err == nil {
		t.Fatal("expected error for nil agent")
	}
}

func TestMemoryStore_SaveAgent_EmptyID(t *testing.T) {
	store := NewMemoryStore()
	err := store.SaveAgent(&AgentInfo{})
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestMemoryStore_GetAgent_NotFound(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.GetAgent("nonexistent")
	if !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("expected ErrAgentNotFound, got %v", err)
	}
}

func TestMemoryStore_GetAgent_EmptyID(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.GetAgent("")
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestMemoryStore_ListAgents(t *testing.T) {
	store := NewMemoryStore()

	_ = store.SaveAgent(&AgentInfo{ID: "a", Status: "active"})
	_ = store.SaveAgent(&AgentInfo{ID: "b", Status: "active"})

	agents, err := store.ListAgents()
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
}

func TestMemoryStore_DeleteAgent_Success(t *testing.T) {
	store := NewMemoryStore()

	_ = store.SaveAgent(&AgentInfo{ID: "del-me", Status: "active"})

	if err := store.DeleteAgent("del-me"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	_, err := store.GetAgent("del-me")
	if !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("expected ErrAgentNotFound after delete, got %v", err)
	}
}

func TestMemoryStore_DeleteAgent_NotFound(t *testing.T) {
	store := NewMemoryStore()
	err := store.DeleteAgent("nonexistent")
	if !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("expected ErrAgentNotFound, got %v", err)
	}
}

func TestMemoryStore_DeleteAgent_EmptyID(t *testing.T) {
	store := NewMemoryStore()
	err := store.DeleteAgent("")
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

// --- MemoryStore code tests ---

func TestMemoryStore_SaveCode_EmptyHash(t *testing.T) {
	store := NewMemoryStore()
	if err := store.SaveCode("", time.Now().Add(time.Hour)); !errors.Is(err, ErrEnrollmentCodeInvalid) {
		t.Errorf("expected ErrEnrollmentCodeInvalid, got %v", err)
	}
}

func TestMemoryStore_SavePending_Nil(t *testing.T) {
	store := NewMemoryStore()
	if err := store.SavePending(nil); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got %v", err)
	}
}

func TestMemoryStore_SaveAndConsumeCode(t *testing.T) {
	store := NewMemoryStore()

	if err := store.SaveCode("hash-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	if err := store.ConsumeCode("hash-1"); err != nil {
		t.Fatalf("ConsumeCode: %v", err)
	}
	if err := store.ConsumeCode("hash-1"); !errors.Is(err, ErrEnrollmentCodeInvalid) {
		t.Errorf("expected ErrEnrollmentCodeInvalid on reuse, got %v", err)
	}
}

func TestMemoryStore_ConsumeCode_Invalid(t *testing.T) {
	store := NewMemoryStore()
	if err := store.ConsumeCode("never-saved"); !errors.Is(err, ErrEnrollmentCodeInvalid) {
		t.Errorf("expected ErrEnrollmentCodeInvalid, got %v", err)
	}
}

func TestMemoryStore_ConsumeCode_Expired(t *testing.T) {
	store := NewMemoryStore()
	if err := store.SaveCode("expired", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	if err := store.ConsumeCode("expired"); !errors.Is(err, ErrEnrollmentCodeExpired) {
		t.Errorf("expected ErrEnrollmentCodeExpired, got %v", err)
	}
}

func TestMemoryStore_CleanExpiredCodes(t *testing.T) {
	store := NewMemoryStore()
	_ = store.SaveCode("expired", time.Now().Add(-time.Minute))
	_ = store.SaveCode("valid", time.Now().Add(time.Hour))

	removed, err := store.CleanExpiredCodes()
	if err != nil {
		t.Fatalf("CleanExpiredCodes: %v", err)
	}
	if removed != 1 {
		t.Errorf("expected 1 removed code, got %d", removed)
	}
}

// --- MemoryStore pending tests ---

func TestMemoryStore_SaveAndGetPending(t *testing.T) {
	store := NewMemoryStore()
	p := &PendingEnrollment{ID: "req-1", Fingerprint: "fp-1", Status: "pending"}
	if err := store.SavePending(p); err != nil {
		t.Fatalf("SavePending: %v", err)
	}
	got, err := store.GetPending("req-1")
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if got.Fingerprint != "fp-1" {
		t.Errorf("expected fingerprint 'fp-1', got %q", got.Fingerprint)
	}
}

func TestMemoryStore_GetPending_NotFound(t *testing.T) {
	store := NewMemoryStore()
	if _, err := store.GetPending("nonexistent"); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got %v", err)
	}
}

func TestMemoryStore_ListPending(t *testing.T) {
	store := NewMemoryStore()
	_ = store.SavePending(&PendingEnrollment{ID: "r1", Status: "pending"})
	_ = store.SavePending(&PendingEnrollment{ID: "r2", Status: "pending"})

	all, err := store.ListPending()
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 pending requests, got %d", len(all))
	}
}

func TestMemoryStore_DeletePending_Success(t *testing.T) {
	store := NewMemoryStore()
	_ = store.SavePending(&PendingEnrollment{ID: "to-delete", Status: "pending"})
	if err := store.DeletePending("to-delete"); err != nil {
		t.Fatalf("DeletePending: %v", err)
	}
	if _, err := store.GetPending("to-delete"); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound after delete, got %v", err)
	}
}

func TestMemoryStore_DeletePending_NotFound(t *testing.T) {
	store := NewMemoryStore()
	if err := store.DeletePending("nonexistent"); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got %v", err)
	}
}
