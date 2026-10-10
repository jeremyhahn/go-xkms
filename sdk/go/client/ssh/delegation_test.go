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
// pkg/ssh/* for the SDK surface: each pins that the
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
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestNewEmbeddedFile_PersistsAcrossReopen verifies the file-backed client
// creates its root directory and that a key written through one client is
// read back by a second client opened over the same directory.
func TestNewEmbeddedFile_PersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "ekey-store")
	client, err := sdkssh.NewEmbeddedFile(sdkssh.EmbeddedFileOptions{RootDir: root})
	if err != nil {
		t.Fatalf("NewEmbeddedFile: %v", err)
	}
	if _, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "laptop", Algorithm: "ed25519",
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := sdkssh.NewEmbeddedFile(sdkssh.EmbeddedFileOptions{RootDir: root})
	if err != nil {
		t.Fatalf("NewEmbeddedFile (reopen): %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if _, err := reopened.Keys().Get(ctx, sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"}); err != nil {
		t.Fatalf("Get after reopen: %v", err)
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

// TestNewEmbeddedFile_MkdirFailureIsWrapped forces MkdirAll to fail with
// ENOTDIR (a regular file where a directory is expected) — root-proof, unlike
// permission bits — and verifies the failure surfaces as a typed
// *EmbeddedFileStoreError.
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

// TestNewConsoleSessionStore_RejectsNilDAOFactory pins the ErrNilDAOFactory
// forwarding from pkg/ssh/sessions.
func TestNewConsoleSessionStore_RejectsNilDAOFactory(t *testing.T) {
	_, err := sdkssh.NewConsoleSessionStore(nil)
	if !errors.Is(err, pkgsessions.ErrNilDAOFactory) || !errors.Is(err, sdkssh.ErrConsoleSessionNilDAOFactory) {
		t.Fatalf("expected ErrNilDAOFactory, got %v", err)
	}
}

// TestNewConsoleSessionStore_Opens verifies the happy path returns a usable
// store over an in-memory DAO factory.
func TestNewConsoleSessionStore_Opens(t *testing.T) {
	store, err := sdkssh.NewConsoleSessionStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewConsoleSessionStore: %v", err)
	}
	if _, err := store.List(); err != nil {
		t.Fatalf("List on freshly opened store: %v", err)
	}
}

// TestNewProfileStore_Opens verifies the happy path returns a usable store
// over an in-memory DAO factory.
func TestNewProfileStore_Opens(t *testing.T) {
	store, err := sdkssh.NewProfileStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewProfileStore: %v", err)
	}
	if _, err := store.List(); err != nil {
		t.Fatalf("List on freshly opened store: %v", err)
	}
}

// TestNewProfileStore_RejectsNilDAOFactory pins the ErrProfileNilDAOFactory
// forwarding from pkg/ssh/profile.
func TestNewProfileStore_RejectsNilDAOFactory(t *testing.T) {
	_, err := sdkssh.NewProfileStore(nil)
	if !errors.Is(err, sdkssh.ErrProfileNilDAOFactory) {
		t.Fatalf("expected ErrProfileNilDAOFactory, got %v", err)
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
