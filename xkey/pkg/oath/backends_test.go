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

package oath

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestOpenStores_PartitionsByBackend(t *testing.T) {
	storage := xkms.NewStorageMemory()
	store, err := OpenStores(storage, "", []string{DefaultBackendID, "token1"}, DefaultBackendID)
	if err != nil {
		t.Fatalf("OpenStores: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Add(createTestCredential("github", "GitHub")); err != nil {
		t.Fatalf("add default: %v", err)
	}
	if err := store.Add(newCompositeTestCredential("vpn", "VPN", "token1")); err != nil {
		t.Fatalf("add token1: %v", err)
	}

	ctx := context.Background()
	for key, want := range map[string]bool{
		"oath/github.json":        true,
		"oath@token1/vpn.json":    true,
		"oath/vpn.json":           false,
		"oath@token1/github.json": false,
	} {
		got, err := storage.Exists(ctx, key)
		if err != nil {
			t.Fatalf("Exists(%q): %v", key, err)
		}
		if got != want {
			t.Errorf("Exists(%q) = %v, want %v", key, got, want)
		}
	}

	creds, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(creds) != 2 || creds[0].BackendID != DefaultBackendID || creds[1].BackendID != "token1" {
		t.Fatalf("List = %+v, want GitHub on software then VPN on token1", creds)
	}
}

func TestOpenStores_LegacyCredentialOnDefault(t *testing.T) {
	storage := xkms.NewStorageMemory()

	// A credential written before multi-backend routing: "oath/" prefix and
	// no BackendID.
	legacy, err := NewBackendStore(storage, "oath/")
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	if err := legacy.Add(createTestCredential("github", "GitHub")); err != nil {
		t.Fatalf("legacy add: %v", err)
	}

	store, err := OpenStores(storage, "", []string{DefaultBackendID, "token1"}, "token1")
	if err != nil {
		t.Fatalf("OpenStores: %v", err)
	}
	cred, err := store.Get("GitHub")
	if err != nil {
		t.Fatalf("Get legacy: %v", err)
	}
	if cred.BackendID != DefaultBackendID {
		t.Errorf("BackendID = %q, want %q", cred.BackendID, DefaultBackendID)
	}
	if err := store.Delete("GitHub"); err != nil {
		t.Fatalf("Delete legacy: %v", err)
	}
}

func TestOpenStores_InvalidBackendID(t *testing.T) {
	for _, id := range []string{"", "..", "a/b", `a\b`, "tok en"} {
		_, err := OpenStores(xkms.NewStorageMemory(), "", []string{DefaultBackendID, id}, DefaultBackendID)
		var backendErr *BackendError
		if !errors.Is(err, ErrInvalidBackendID) || !errors.As(err, &backendErr) || backendErr.BackendID != id {
			t.Errorf("id %q: err = %v, want ErrInvalidBackendID naming it", id, err)
		}
	}
}

func TestOpenStores_NoStorageNoPath(t *testing.T) {
	// Without the barrier the set is file-backed, and a file store needs a path.
	_, err := OpenStores(nil, "", []string{DefaultBackendID}, DefaultBackendID)
	if !errors.Is(err, ErrBackendStoreOpen) || !errors.Is(err, ErrInvalidStorePath) {
		t.Fatalf("err = %v, want ErrBackendStoreOpen wrapping ErrInvalidStorePath", err)
	}
}

func TestFilePartitionPath_NamedAfterStoreFile(t *testing.T) {
	dir := t.TempDir()
	cases := []struct{ path, id, want string }{
		{filepath.Join(dir, "oath.json"), DefaultBackendID, filepath.Join(dir, "oath.json")},
		{filepath.Join(dir, "oath.json"), "token1", filepath.Join(dir, "oath@token1.json")},
		{filepath.Join(dir, "a.json"), "token1", filepath.Join(dir, "a@token1.json")},
		{filepath.Join(dir, "creds"), "token1", filepath.Join(dir, "creds@token1")},
	}
	for _, tc := range cases {
		got, err := FilePartitionPath(tc.path, tc.id)
		if err != nil || got != tc.want {
			t.Errorf("FilePartitionPath(%q, %q) = %q, %v; want %q", tc.path, tc.id, got, err, tc.want)
		}
	}
}

func TestFilePartitionPath_RefusesAliasingPath(t *testing.T) {
	// b@token1.json is the token1 partition of b.json, so it may not be a
	// store of its own.
	for _, path := range []string{"", filepath.Join(t.TempDir(), "b@token1.json")} {
		if _, err := FilePartitionPath(path, DefaultBackendID); !errors.Is(err, ErrInvalidStorePath) {
			t.Errorf("FilePartitionPath(%q) err = %v, want ErrInvalidStorePath", path, err)
		}
	}
}

func TestOpenStores_TwoStoresInOneDirectoryAreIsolated(t *testing.T) {
	dir := t.TempDir()
	ids := []string{DefaultBackendID, "token1"}
	storeA, err := OpenStores(nil, filepath.Join(dir, "a.json"), ids, DefaultBackendID)
	if err != nil {
		t.Fatalf("open a: %v", err)
	}
	storeB, err := OpenStores(nil, filepath.Join(dir, "b.json"), ids, DefaultBackendID)
	if err != nil {
		t.Fatalf("open b: %v", err)
	}
	if err := storeA.Add(newCompositeTestCredential("vpn", "VPN", "token1")); err != nil {
		t.Fatalf("add to a: %v", err)
	}

	creds, err := storeB.List()
	if err != nil || len(creds) != 0 {
		t.Fatalf("b.List() = %d credentials, %v; want none of a's", len(creds), err)
	}
	if err := storeB.Delete("vpn"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("b.Delete(vpn) err = %v, want ErrCredentialNotFound", err)
	}
	if _, err := storeA.Get("vpn"); err != nil {
		t.Fatalf("a.Get(vpn) after b's delete: %v", err)
	}
}

func TestCompositeStore_Add_ConcurrentDuplicateOneWins(t *testing.T) {
	// Each round races one ID and name onto two backends; the cross-backend
	// uniqueness check must admit exactly one of them every time.
	backends := []string{DefaultBackendID, "token1"}
	for range 50 {
		store, err := OpenStores(xkms.NewStorageMemory(), "", backends, DefaultBackendID)
		if err != nil {
			t.Fatalf("OpenStores: %v", err)
		}
		errs := make([]error, len(backends))
		var wg sync.WaitGroup
		for i, backend := range backends {
			wg.Go(func() {
				errs[i] = store.Add(newCompositeTestCredential("vpn", "VPN", backend))
			})
		}
		wg.Wait()

		var added, refused int
		for _, err := range errs {
			switch {
			case err == nil:
				added++
			case errors.Is(err, ErrCredentialExists):
				refused++
			default:
				t.Fatalf("Add: unexpected error %v", err)
			}
		}
		if added != 1 || refused != 1 {
			t.Fatalf("added %d, refused %d; want exactly one of each", added, refused)
		}
	}
}

func TestOpenStores_PartitionFiles(t *testing.T) {
	dir := t.TempDir()
	defaultPath := filepath.Join(dir, "oath.json")
	store, err := OpenStores(nil, defaultPath, []string{DefaultBackendID, "token1"}, DefaultBackendID)
	if err != nil {
		t.Fatalf("OpenStores: %v", err)
	}
	if err := store.Add(createTestCredential("github", "GitHub")); err != nil {
		t.Fatalf("add default: %v", err)
	}
	if err := store.Add(newCompositeTestCredential("vpn", "VPN", "token1")); err != nil {
		t.Fatalf("add token1: %v", err)
	}
	for _, name := range []string{"oath.json", "oath@token1.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected partition file %s: %v", name, err)
		}
	}

	// A fresh composite over the same files reads both partitions back.
	reopened, err := OpenStores(nil, defaultPath, []string{DefaultBackendID, "token1"}, DefaultBackendID)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	cred, err := reopened.Get("vpn")
	if err != nil || cred.BackendID != "token1" {
		t.Fatalf("Get(vpn) = %+v, %v; want token1", cred, err)
	}
}

func TestOpenStores_UnreadableFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "oath@token1.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := OpenStores(nil, filepath.Join(dir, "oath.json"), []string{DefaultBackendID, "token1"}, DefaultBackendID)
	var backendErr *BackendError
	if !errors.As(err, &backendErr) || backendErr.BackendID != "token1" || !errors.Is(err, ErrBackendStoreOpen) {
		t.Fatalf("err = %v, want ErrBackendStoreOpen naming token1", err)
	}
}

func TestCompositeStore_Add_UnknownBackendNamesIt(t *testing.T) {
	store, err := OpenStores(xkms.NewStorageMemory(), "", []string{DefaultBackendID}, DefaultBackendID)
	if err != nil {
		t.Fatalf("OpenStores: %v", err)
	}
	err = store.Add(newCompositeTestCredential("vpn", "VPN", "nosuch"))
	var backendErr *BackendError
	if !errors.Is(err, ErrStoreNotFound) || !errors.As(err, &backendErr) || backendErr.BackendID != "nosuch" {
		t.Fatalf("err = %v, want ErrStoreNotFound naming nosuch", err)
	}
	if got := err.Error(); got != `oath: store not found for backend: "nosuch"` {
		t.Errorf("Error() = %q", got)
	}
}

func TestCompositeStore_Add_DuplicateAcrossBackends(t *testing.T) {
	store, err := OpenStores(xkms.NewStorageMemory(), "", []string{DefaultBackendID, "token1"}, DefaultBackendID)
	if err != nil {
		t.Fatalf("OpenStores: %v", err)
	}
	if err := store.Add(createTestCredential("github", "GitHub")); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := store.Add(newCompositeTestCredential("gh2", "github", "token1")); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("same name on another backend: err = %v, want ErrCredentialExists", err)
	}
	if err := store.Add(newCompositeTestCredential("github", "Other", "token1")); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("same ID on another backend: err = %v, want ErrCredentialExists", err)
	}
}
