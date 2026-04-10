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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMigrateFileStoreToDAO_Success(t *testing.T) {
	dir := t.TempDir()
	logger := testLogger()

	// Write two agent JSON files.
	agents := []*AgentInfo{
		{
			ID:                     "agent-001",
			Name:                   "first-agent",
			Address:                "10.0.0.1:9443",
			CertificateFingerprint: "fp001",
			Status:                 "active",
			EnrolledAt:             time.Now().UTC().Truncate(time.Second),
			LastSeen:               time.Now().UTC().Truncate(time.Second),
		},
		{
			ID:                     "agent-002",
			Name:                   "second-agent",
			Address:                "10.0.0.2:9443",
			CertificateFingerprint: "fp002",
			Status:                 "active",
			EnrolledAt:             time.Now().UTC().Truncate(time.Second),
			LastSeen:               time.Now().UTC().Truncate(time.Second),
		},
	}
	for _, a := range agents {
		data, err := json.MarshalIndent(a, "", "  ")
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		path := filepath.Join(dir, a.ID+".json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	store := newTestDAOStore(t)
	result, err := MigrateFileStoreToDAO(dir, store, logger)
	if err != nil {
		t.Fatalf("migration error: %v", err)
	}

	if result.Total != 2 {
		t.Errorf("Total = %d, want 2", result.Total)
	}
	if result.Migrated != 2 {
		t.Errorf("Migrated = %d, want 2", result.Migrated)
	}
	if result.Skipped != 0 {
		t.Errorf("Skipped = %d, want 0", result.Skipped)
	}

	// Verify agents are accessible via DAO store.
	got, err := store.GetAgent("agent-001")
	if err != nil {
		t.Fatalf("GetAgent(agent-001) error: %v", err)
	}
	if got.Name != "first-agent" {
		t.Errorf("Name = %q, want %q", got.Name, "first-agent")
	}

	got2, err := store.GetAgent("agent-002")
	if err != nil {
		t.Fatalf("GetAgent(agent-002) error: %v", err)
	}
	if got2.Name != "second-agent" {
		t.Errorf("Name = %q, want %q", got2.Name, "second-agent")
	}
}

func TestMigrateFileStoreToDAO_MalformedFile(t *testing.T) {
	dir := t.TempDir()
	logger := testLogger()

	// Write one valid and one malformed file.
	valid := &AgentInfo{
		ID:     "good-agent",
		Name:   "good",
		Status: "active",
	}
	data, _ := json.Marshal(valid)
	os.WriteFile(filepath.Join(dir, "good.json"), data, 0600)
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte("not json{{{"), 0600)

	store := newTestDAOStore(t)
	result, err := MigrateFileStoreToDAO(dir, store, logger)
	if err != nil {
		t.Fatalf("migration error: %v", err)
	}

	if result.Total != 2 {
		t.Errorf("Total = %d, want 2", result.Total)
	}
	if result.Migrated != 1 {
		t.Errorf("Migrated = %d, want 1", result.Migrated)
	}
	if result.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", result.Skipped)
	}
	if _, ok := result.Errors["bad.json"]; !ok {
		t.Error("expected error entry for bad.json")
	}
}

func TestMigrateFileStoreToDAO_NonExistentDir(t *testing.T) {
	logger := testLogger()
	store := newTestDAOStore(t)

	result, err := MigrateFileStoreToDAO("/tmp/no-such-dir-agent-migrate-test", store, logger)
	if err != nil {
		t.Fatalf("expected nil error for non-existent dir, got: %v", err)
	}
	if result.Total != 0 {
		t.Errorf("Total = %d, want 0", result.Total)
	}
}

func TestMigrateFileStoreToDAO_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	logger := testLogger()
	store := newTestDAOStore(t)

	result, err := MigrateFileStoreToDAO(dir, store, logger)
	if err != nil {
		t.Fatalf("migration error: %v", err)
	}
	if result.Total != 0 {
		t.Errorf("Total = %d, want 0", result.Total)
	}
	if result.Migrated != 0 {
		t.Errorf("Migrated = %d, want 0", result.Migrated)
	}
}

func TestMigrateFileStoreToDAO_InvalidParams(t *testing.T) {
	logger := testLogger()
	store := newTestDAOStore(t)

	t.Run("EmptySourceDir", func(t *testing.T) {
		_, err := MigrateFileStoreToDAO("", store, logger)
		if err != ErrMigrationSourceDir {
			t.Fatalf("expected ErrMigrationSourceDir, got: %v", err)
		}
	})

	t.Run("NilStore", func(t *testing.T) {
		_, err := MigrateFileStoreToDAO("/tmp", nil, logger)
		if err != ErrMigrationNilStore {
			t.Fatalf("expected ErrMigrationNilStore, got: %v", err)
		}
	})

	t.Run("NilLogger", func(t *testing.T) {
		_, err := MigrateFileStoreToDAO("/tmp", store, nil)
		if err != ErrMigrationNilLogger {
			t.Fatalf("expected ErrMigrationNilLogger, got: %v", err)
		}
	})
}

func TestMigrateFileStoreToDAO_EmptyAgentID(t *testing.T) {
	dir := t.TempDir()
	logger := testLogger()

	// Write a file with an empty agent ID.
	agent := &AgentInfo{
		ID:     "",
		Name:   "no-id-agent",
		Status: "active",
	}
	data, _ := json.Marshal(agent)
	os.WriteFile(filepath.Join(dir, "empty-id.json"), data, 0600)

	store := newTestDAOStore(t)
	result, err := MigrateFileStoreToDAO(dir, store, logger)
	if err != nil {
		t.Fatalf("migration error: %v", err)
	}

	if result.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", result.Skipped)
	}
	if result.Migrated != 0 {
		t.Errorf("Migrated = %d, want 0", result.Migrated)
	}
}

func TestMigrateFileStoreToDAO_SkipsDirectories(t *testing.T) {
	dir := t.TempDir()
	logger := testLogger()

	// Create a subdirectory (should be skipped).
	os.MkdirAll(filepath.Join(dir, "subdir"), 0700)

	// Create a non-JSON file (should be skipped).
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello"), 0600)

	// Create one valid agent.
	agent := &AgentInfo{ID: "valid-agent", Name: "valid", Status: "active"}
	data, _ := json.Marshal(agent)
	os.WriteFile(filepath.Join(dir, "valid.json"), data, 0600)

	store := newTestDAOStore(t)
	result, err := MigrateFileStoreToDAO(dir, store, logger)
	if err != nil {
		t.Fatalf("migration error: %v", err)
	}

	if result.Total != 1 {
		t.Errorf("Total = %d, want 1 (dirs and non-JSON skipped)", result.Total)
	}
	if result.Migrated != 1 {
		t.Errorf("Migrated = %d, want 1", result.Migrated)
	}
}

func TestMigrateFileStoreToDAO_Idempotent(t *testing.T) {
	dir := t.TempDir()
	logger := testLogger()

	agent := &AgentInfo{
		ID:     "idempotent-agent",
		Name:   "original",
		Status: "active",
	}
	data, _ := json.Marshal(agent)
	os.WriteFile(filepath.Join(dir, "agent.json"), data, 0600)

	store := newTestDAOStore(t)

	// Run migration twice.
	for i := 0; i < 2; i++ {
		result, err := MigrateFileStoreToDAO(dir, store, logger)
		if err != nil {
			t.Fatalf("migration %d error: %v", i+1, err)
		}
		if result.Migrated != 1 {
			t.Errorf("migration %d: Migrated = %d, want 1", i+1, result.Migrated)
		}
	}

	// Should still have exactly one agent.
	list, err := store.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents() error: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("ListAgents() = %d agents, want 1 after idempotent migration", len(list))
	}
}
