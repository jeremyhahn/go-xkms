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

package xkms

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestNewEmbeddedService_Success confirms the one-call constructor wires a
// file-backed software backend under KeyDir and registers it as the default
// backend, matching what NewEmbeddedClient hands to NewEmbedded.
func TestNewEmbeddedService_Success(t *testing.T) {
	dir := t.TempDir()
	defer Reset()

	svc, err := NewEmbeddedService(EmbeddedServiceConfig{KeyDir: dir})
	if err != nil {
		t.Fatalf("NewEmbeddedService() returned error: %v", err)
	}
	if svc == nil {
		t.Fatal("NewEmbeddedService() returned nil servicer")
	}

	backends, err := svc.ListBackends(context.Background())
	if err != nil {
		t.Fatalf("ListBackends() returned error: %v", err)
	}
	found := false
	for _, b := range backends {
		if b.ID == string(ServiceBackendSoftware) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected default backend %q in %v", ServiceBackendSoftware, backends)
	}

	if _, err := os.Stat(filepath.Join(dir, "certs")); err != nil {
		t.Errorf("expected certs dir to be created under KeyDir: %v", err)
	}
}

// TestNewEmbeddedService_CustomBackendName confirms a caller-supplied
// BackendName is used verbatim as the registered/default backend id instead
// of the "software" fallback.
func TestNewEmbeddedService_CustomBackendName(t *testing.T) {
	dir := t.TempDir()
	defer Reset()

	svc, err := NewEmbeddedService(EmbeddedServiceConfig{KeyDir: dir, BackendName: "custom"})
	if err != nil {
		t.Fatalf("NewEmbeddedService() returned error: %v", err)
	}

	backends, err := svc.ListBackends(context.Background())
	if err != nil {
		t.Fatalf("ListBackends() returned error: %v", err)
	}
	found := false
	for _, b := range backends {
		if b.ID == "custom" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected backend %q in %v", "custom", backends)
	}
}

// TestNewEmbeddedService_KeyStorageError confirms a KeyDir that cannot be
// created as a directory (because a path component is an existing regular
// file) is surfaced as an error rather than panicking, exercising the
// default-KeyStorage NewFileStorageBackend failure branch.
func TestNewEmbeddedService_KeyStorageError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("failed to create blocker file: %v", err)
	}

	_, err := NewEmbeddedService(EmbeddedServiceConfig{KeyDir: filepath.Join(blocker, "keys")})
	if err == nil {
		t.Fatal("expected an error when KeyDir cannot be created")
	}
}

// TestNewEmbeddedService_CertStorageError supplies a working KeyStorage
// explicitly (skipping the default-KeyStorage branch) while KeyDir itself is
// blocked by a regular file, exercising the certStorage
// NewFileStorageBackend failure branch independently of the KeyStorage one.
func TestNewEmbeddedService_CertStorageError(t *testing.T) {
	dir := t.TempDir()
	keyStorageDir := filepath.Join(dir, "keys")
	keyStorage, err := NewFileStorageBackend(keyStorageDir)
	if err != nil {
		t.Fatalf("failed to build key storage: %v", err)
	}

	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("failed to create blocker file: %v", err)
	}

	_, err = NewEmbeddedService(EmbeddedServiceConfig{KeyDir: blocker, KeyStorage: keyStorage})
	if err == nil {
		t.Fatal("expected an error when cert storage cannot be created")
	}
}

// TestNewEmbeddedClient_Success confirms the one-call convenience wires the
// embedded service straight into a connected Client.
func TestNewEmbeddedClient_Success(t *testing.T) {
	dir := t.TempDir()
	defer Reset()

	client, err := NewEmbeddedClient(EmbeddedServiceConfig{KeyDir: dir})
	if err != nil {
		t.Fatalf("NewEmbeddedClient() returned error: %v", err)
	}
	if client == nil {
		t.Fatal("NewEmbeddedClient() returned nil client")
	}

	resp, err := client.ListBackends(context.Background())
	if err != nil {
		t.Fatalf("ListBackends() returned error: %v", err)
	}
	if len(resp.Backends) == 0 {
		t.Error("expected at least one backend")
	}
}

// TestNewEmbeddedClient_ServiceError confirms NewEmbeddedClient propagates a
// NewEmbeddedService failure instead of calling NewEmbedded with a nil
// service.
func TestNewEmbeddedClient_ServiceError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("failed to create blocker file: %v", err)
	}

	client, err := NewEmbeddedClient(EmbeddedServiceConfig{KeyDir: filepath.Join(blocker, "keys")})
	if err == nil {
		t.Fatal("expected an error when the embedded service cannot be built")
	}
	if client != nil {
		t.Errorf("expected nil client on error, got %v", client)
	}
}
