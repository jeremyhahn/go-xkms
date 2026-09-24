// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

// This file exercises the thin re-export/delegation constructors that wrap
// pkg/ssh/* and pkg/storage/file for the SDK surface: each pins that the
// wrapper forwards arguments and errors correctly, without duplicating the
// wrapped package's own behavioral tests.
package ssh_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pkgsessions "github.com/jeremyhahn/go-xkms/pkg/ssh/sessions"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestNewFileStorage_CreatesRootAndOpens verifies the happy path: the root
// directory is created (mode 0700) and a usable Backend is returned.
func TestNewFileStorage_CreatesRootAndOpens(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ssh-store")
	backend, err := sdkssh.NewFileStorage(root)
	if err != nil {
		t.Fatalf("NewFileStorage: %v", err)
	}
	defer func() { _ = backend.Close() }()

	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("root dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("root is not a directory")
	}

	if err := backend.Put(context.Background(), "k", []byte("v")); err != nil {
		t.Fatalf("Put on opened backend: %v", err)
	}
}

// TestNewFileStorage_EmptyRootDir rejects an empty root with NilInputError.
func TestNewFileStorage_EmptyRootDir(t *testing.T) {
	_, err := sdkssh.NewFileStorage("")
	var nie *sdkssh.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected *NilInputError, got %T: %v", err, err)
	}
}

// TestNewFileStorage_MkdirFailureIsWrapped forces MkdirAll to fail with
// ENOTDIR (a regular file where a directory is expected) — root-proof, unlike
// permission bits — and verifies the failure surfaces as a typed
// *EmbeddedFileStoreError wrapping the underlying error.
func TestNewFileStorage_MkdirFailureIsWrapped(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	root := filepath.Join(blocker, "child")

	_, err := sdkssh.NewFileStorage(root)
	var fse *sdkssh.EmbeddedFileStoreError
	if !errors.As(err, &fse) {
		t.Fatalf("expected *EmbeddedFileStoreError, got %T: %v", err, err)
	}
	if fse.Op != "mkdir" || fse.Path != root {
		t.Fatalf("unexpected fields: op=%q path=%q", fse.Op, fse.Path)
	}
	if fse.Unwrap() == nil {
		t.Fatalf("expected wrapped error, got nil")
	}
}

// TestNewEmbeddedFile_CreatesRootAndOpens verifies the happy path
// constructs a usable Client backed by the file directory.
func TestNewEmbeddedFile_CreatesRootAndOpens(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ekey-store")
	client, err := sdkssh.NewEmbeddedFile(sdkssh.EmbeddedFileOptions{RootDir: root})
	if err != nil {
		t.Fatalf("NewEmbeddedFile: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{}); err != nil {
		t.Fatalf("List on file-backed embedded client: %v", err)
	}
}

// TestNewEmbeddedFile_EmptyRootDir rejects an empty root with NilInputError.
func TestNewEmbeddedFile_EmptyRootDir(t *testing.T) {
	_, err := sdkssh.NewEmbeddedFile(sdkssh.EmbeddedFileOptions{})
	var nie *sdkssh.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected *NilInputError, got %T: %v", err, err)
	}
}

// TestNewEmbeddedFile_MkdirFailureIsWrapped mirrors
// TestNewFileStorage_MkdirFailureIsWrapped for the embedded-file constructor's
// own mkdir call.
func TestNewEmbeddedFile_MkdirFailureIsWrapped(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	root := filepath.Join(blocker, "child")

	_, err := sdkssh.NewEmbeddedFile(sdkssh.EmbeddedFileOptions{RootDir: root})
	var fse *sdkssh.EmbeddedFileStoreError
	if !errors.As(err, &fse) {
		t.Fatalf("expected *EmbeddedFileStoreError, got %T: %v", err, err)
	}
	if fse.Op != "mkdir" {
		t.Fatalf("expected op=mkdir, got %q", fse.Op)
	}
}

// TestNewConsoleSessionStore_RejectsNilBackend pins the ErrNilBackend
// forwarding from pkg/ssh/sessions.
func TestNewConsoleSessionStore_RejectsNilBackend(t *testing.T) {
	_, err := sdkssh.NewConsoleSessionStore(nil)
	if !errors.Is(err, pkgsessions.ErrNilBackend) {
		t.Fatalf("expected pkgsessions.ErrNilBackend, got %v", err)
	}
}

// TestNewConsoleSessionStore_Opens verifies the happy path returns a usable
// store over an in-memory backend.
func TestNewConsoleSessionStore_Opens(t *testing.T) {
	store, err := sdkssh.NewConsoleSessionStore(storage.NewMemory())
	if err != nil {
		t.Fatalf("NewConsoleSessionStore: %v", err)
	}
	if _, err := store.List(); err != nil {
		t.Fatalf("List on freshly opened store: %v", err)
	}
}

// TestNewProfileStore_Opens verifies the happy path returns a usable store
// over an in-memory backend.
func TestNewProfileStore_Opens(t *testing.T) {
	store, err := sdkssh.NewProfileStore(storage.NewMemory())
	if err != nil {
		t.Fatalf("NewProfileStore: %v", err)
	}
	if _, err := store.List(); err != nil {
		t.Fatalf("List on freshly opened store: %v", err)
	}
}

// TestNewProfileStore_RejectsNilBackend pins the ErrProfileNilBackend
// forwarding from pkg/ssh/profile.
func TestNewProfileStore_RejectsNilBackend(t *testing.T) {
	_, err := sdkssh.NewProfileStore(nil)
	if !errors.Is(err, sdkssh.ErrProfileNilBackend) {
		t.Fatalf("expected ErrProfileNilBackend, got %v", err)
	}
}

// TestNewBackendProvider_ResolvesThroughResolverFunc verifies the SDK
// constructor wires the supplied KeyProviderResolver into a working
// BackendProvider that forwards ResolveKeyProvider calls.
func TestNewBackendProvider_ResolvesThroughResolverFunc(t *testing.T) {
	wantErr := errors.New("no such backend")
	var gotBackendID string
	resolver := func(_ context.Context, backendID string) (types.KeyProvider, error) {
		gotBackendID = backendID
		return nil, wantErr
	}

	provider, err := sdkssh.NewBackendProvider(resolver)
	if err != nil {
		t.Fatalf("NewBackendProvider: %v", err)
	}

	_, err = provider.GenerateKey(context.Background(), "tpm2", "key-1", "ed25519", 0)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the resolver's error to propagate, got %v", err)
	}
	if gotBackendID != "tpm2" {
		t.Fatalf("resolver saw backendID=%q, want %q", gotBackendID, "tpm2")
	}
}
