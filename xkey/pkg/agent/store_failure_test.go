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

// These tests drive FileStore's typed-error branches for I/O failures other
// than "does not exist" — a class store_test.go's happy-path and not-found
// tests never reach. A silent failure here would mean an agent enrollment
// record, one-time code, or pending request request looks present to the
// filesystem but the caller believes the operation failed differently (or
// vice versa), so the sentinel each branch returns matters, not just that
// an error occurred.
//
// None of these use permission bits (chmod) to force the failure: this
// suite runs as root in CI, and root bypasses every permission check a
// chmod could impose, which would make the fault injection a no-op and the
// assertion below it fail. Each one instead uses a structural condition the
// kernel enforces regardless of caller privilege:
//   - EISDIR: a directory occupies a path the code expects to open/read as
//     a plain file (os.ReadFile, os.WriteFile with O_WRONLY).
//   - ENOTDIR: a regular file occupies a path component the code expects
//     to be a directory (os.ReadDir, or a nested os.WriteFile/os.Open).
//   - ENOTEMPTY: a non-empty directory occupies a path the code expects to
//     os.Remove; the rmdir fallback fails for a non-empty directory no
//     matter who is asking, root included.
//   - ELOOP: a self-referential symlink, for "this entry exists and is
//     listed but cannot be read as a file."

func TestFileStore_GetAgent_ReadPermissionDenied(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	// A directory where the agent record file is expected: os.ReadFile
	// fails with EISDIR independent of privilege level.
	path := filepath.Join(dir, "agents", "agent-1.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_, err = store.GetAgent("agent-1")
	if err == nil {
		t.Fatal("expected an error for an agent path occupied by a directory")
	}
	if errors.Is(err, ErrAgentNotFound) {
		t.Fatalf("a read failure must not be reported as ErrAgentNotFound: %v", err)
	}
	var agentErr *AgentError
	if !errors.As(err, &agentErr) || !errors.Is(agentErr.Err, ErrStoreRead) {
		t.Fatalf("GetAgent() error = %v, want ErrStoreRead", err)
	}
}

func TestFileStore_GetAgent_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	path := filepath.Join(dir, "agents", "agent-1.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = store.GetAgent("agent-1")
	var agentErr *AgentError
	if !errors.As(err, &agentErr) || !errors.Is(agentErr.Err, ErrStoreUnmarshal) {
		t.Fatalf("GetAgent() error = %v, want ErrStoreUnmarshal", err)
	}
}

// TestFileStore_ListAgents_UnreadableDir replaces the agents/ subdirectory
// itself with a regular file, so os.ReadDir fails with ENOTDIR rather than
// a permission error a root test runner would bypass.
func TestFileStore_ListAgents_UnreadableDir(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	agentsDir := filepath.Join(dir, "agents")
	if err := os.RemoveAll(agentsDir); err != nil {
		t.Fatalf("remove agents dir: %v", err)
	}
	if err := os.WriteFile(agentsDir, []byte("blocker"), 0600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	_, err = store.ListAgents()
	var agentErr *AgentError
	if !errors.As(err, &agentErr) || !errors.Is(agentErr.Err, ErrStoreRead) {
		t.Fatalf("ListAgents() error = %v, want ErrStoreRead", err)
	}
}

// TestFileStore_ListAgents_SkipsUnreadableFile proves ListAgents tolerates
// one damaged file in the directory rather than failing the whole listing —
// the same tolerance TestFileStore_ListAgents_IgnoresMalformedJSON already
// proves for a malformed (but readable) file. The damaged entry is a
// self-referential symlink: os.ReadFile on it fails with ELOOP independent
// of privilege level, unlike a chmod-based denial.
func TestFileStore_ListAgents_SkipsUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if err := store.SaveAgent(&AgentInfo{ID: "good"}); err != nil {
		t.Fatalf("SaveAgent: %v", err)
	}
	badPath := filepath.Join(dir, "agents", "unreadable.json")
	if err := os.Symlink(badPath, badPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	agents, err := store.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 1 || agents[0].ID != "good" {
		t.Fatalf("ListAgents() = %+v, want only the readable agent", agents)
	}
}

// TestFileStore_DeleteAgent_RemoveFails replaces the saved agent file with a
// non-empty directory at the same path: os.Remove's rmdir fallback fails
// with ENOTEMPTY for any caller, root included, unlike a chmod-based denial
// on the parent directory.
func TestFileStore_DeleteAgent_RemoveFails(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if err := store.SaveAgent(&AgentInfo{ID: "agent-1"}); err != nil {
		t.Fatalf("SaveAgent: %v", err)
	}
	path := filepath.Join(dir, "agents", "agent-1.json")
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "occupied"), []byte("x"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err = store.DeleteAgent("agent-1")
	var agentErr *AgentError
	if !errors.As(err, &agentErr) || !errors.Is(agentErr.Err, ErrStoreDelete) {
		t.Fatalf("DeleteAgent() error = %v, want ErrStoreDelete", err)
	}
}

// TestFileStore_SaveCode_WriteFails replaces the codes/ subdirectory with a
// regular file, so os.WriteFile fails with ENOTDIR (a path component is not
// a directory) rather than a permission error a root test runner bypasses.
func TestFileStore_SaveCode_WriteFails(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	codesDir := filepath.Join(dir, "codes")
	if err := os.RemoveAll(codesDir); err != nil {
		t.Fatalf("remove codes dir: %v", err)
	}
	if err := os.WriteFile(codesDir, []byte("blocker"), 0600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	err = store.SaveCode("somehash", time.Now().Add(time.Hour))
	var agentErr *AgentError
	if !errors.As(err, &agentErr) || !errors.Is(agentErr.Err, ErrStoreWrite) {
		t.Fatalf("SaveCode() error = %v, want ErrStoreWrite", err)
	}
}

// TestFileStore_ConsumeCode_ReadPermissionDenied puts a directory where the
// code file is expected: os.ReadFile fails with EISDIR independent of
// privilege level.
func TestFileStore_ConsumeCode_ReadPermissionDenied(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	path := filepath.Join(dir, "codes", "somehash.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	err = store.ConsumeCode("somehash")
	if errors.Is(err, ErrEnrollmentCodeInvalid) {
		t.Fatalf("a read failure must not be reported as ErrEnrollmentCodeInvalid: %v", err)
	}
	var agentErr *AgentError
	if !errors.As(err, &agentErr) || !errors.Is(agentErr.Err, ErrStoreRead) {
		t.Fatalf("ConsumeCode() error = %v, want ErrStoreRead", err)
	}
}

func TestFileStore_ConsumeCode_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	path := filepath.Join(dir, "codes", "somehash.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err = store.ConsumeCode("somehash")
	var agentErr *AgentError
	if !errors.As(err, &agentErr) || !errors.Is(agentErr.Err, ErrStoreUnmarshal) {
		t.Fatalf("ConsumeCode() error = %v, want ErrStoreUnmarshal", err)
	}
}

// TestFileStore_CleanExpiredCodes_UnreadableDir replaces the codes/
// subdirectory with a regular file, so os.ReadDir fails with ENOTDIR rather
// than a permission error a root test runner would bypass.
func TestFileStore_CleanExpiredCodes_UnreadableDir(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	codesDir := filepath.Join(dir, "codes")
	if err := os.RemoveAll(codesDir); err != nil {
		t.Fatalf("remove codes dir: %v", err)
	}
	if err := os.WriteFile(codesDir, []byte("blocker"), 0600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	_, err = store.CleanExpiredCodes()
	var agentErr *AgentError
	if !errors.As(err, &agentErr) || !errors.Is(agentErr.Err, ErrStoreRead) {
		t.Fatalf("CleanExpiredCodes() error = %v, want ErrStoreRead", err)
	}
}

// TestFileStore_GetPending_ReadPermissionDenied puts a directory where the
// pending request file is expected: os.ReadFile fails with EISDIR
// independent of privilege level.
func TestFileStore_GetPending_ReadPermissionDenied(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	path := filepath.Join(dir, "pending", "req-1.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_, err = store.GetPending("req-1")
	if errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("a read failure must not be reported as ErrRequestNotFound: %v", err)
	}
	var agentErr *AgentError
	if !errors.As(err, &agentErr) || !errors.Is(agentErr.Err, ErrStoreRead) {
		t.Fatalf("GetPending() error = %v, want ErrStoreRead", err)
	}
}

func TestFileStore_GetPending_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	path := filepath.Join(dir, "pending", "req-1.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = store.GetPending("req-1")
	var agentErr *AgentError
	if !errors.As(err, &agentErr) || !errors.Is(agentErr.Err, ErrStoreUnmarshal) {
		t.Fatalf("GetPending() error = %v, want ErrStoreUnmarshal", err)
	}
}

// TestFileStore_ListPending_UnreadableDir replaces the pending/
// subdirectory with a regular file, so os.ReadDir fails with ENOTDIR rather
// than a permission error a root test runner would bypass.
func TestFileStore_ListPending_UnreadableDir(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	pendingDir := filepath.Join(dir, "pending")
	if err := os.RemoveAll(pendingDir); err != nil {
		t.Fatalf("remove pending dir: %v", err)
	}
	if err := os.WriteFile(pendingDir, []byte("blocker"), 0600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	_, err = store.ListPending()
	var agentErr *AgentError
	if !errors.As(err, &agentErr) || !errors.Is(agentErr.Err, ErrStoreRead) {
		t.Fatalf("ListPending() error = %v, want ErrStoreRead", err)
	}
}

// TestFileStore_ListPending_SkipsUnreadableAndMalformed proves ListPending
// tolerates both a damaged (unreadable) file and a malformed (but readable)
// one in the same listing, matching ListAgents' per-entry tolerance. The
// damaged entry is a self-referential symlink: os.ReadFile on it fails with
// ELOOP independent of privilege level, unlike a chmod-based denial.
func TestFileStore_ListPending_SkipsUnreadableAndMalformed(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if err := store.SavePending(&PendingEnrollment{ID: "good", Status: "pending"}); err != nil {
		t.Fatalf("SavePending: %v", err)
	}
	unreadablePath := filepath.Join(dir, "pending", "unreadable.json")
	if err := os.Symlink(unreadablePath, unreadablePath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	malformedPath := filepath.Join(dir, "pending", "malformed.json")
	if err := os.WriteFile(malformedPath, []byte("{not-json"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := store.ListPending()
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(result) != 1 || result[0].ID != "good" {
		t.Fatalf("ListPending() = %+v, want only the readable, well-formed entry", result)
	}
}

// TestFileStore_DeletePending_RemoveFails replaces the saved pending-request
// file with a non-empty directory at the same path: os.Remove's rmdir
// fallback fails with ENOTEMPTY for any caller, root included, unlike a
// chmod-based denial on the parent directory.
func TestFileStore_DeletePending_RemoveFails(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if err := store.SavePending(&PendingEnrollment{ID: "req-1", Status: "pending"}); err != nil {
		t.Fatalf("SavePending: %v", err)
	}
	path := filepath.Join(dir, "pending", "req-1.json")
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "occupied"), []byte("x"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err = store.DeletePending("req-1")
	var agentErr *AgentError
	if !errors.As(err, &agentErr) || !errors.Is(agentErr.Err, ErrStoreDelete) {
		t.Fatalf("DeletePending() error = %v, want ErrStoreDelete", err)
	}
}

// --- MemoryStore empty-ID branches store_test.go does not cover ---

func TestMemoryStore_ConsumeCode_EmptyHash(t *testing.T) {
	store := NewMemoryStore()
	if err := store.ConsumeCode(""); !errors.Is(err, ErrEnrollmentCodeInvalid) {
		t.Errorf("ConsumeCode(\"\") error = %v, want ErrEnrollmentCodeInvalid", err)
	}
}

func TestMemoryStore_GetPending_EmptyID(t *testing.T) {
	store := NewMemoryStore()
	if _, err := store.GetPending(""); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("GetPending(\"\") error = %v, want ErrRequestNotFound", err)
	}
}

func TestMemoryStore_DeletePending_EmptyID(t *testing.T) {
	store := NewMemoryStore()
	if err := store.DeletePending(""); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("DeletePending(\"\") error = %v, want ErrRequestNotFound", err)
	}
}
