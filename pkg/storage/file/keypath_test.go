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

package file

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// escapableKeyCases covers the key shapes whose on-disk filename differs from
// the raw key because the go-qrdb file engine percent-escapes them. The
// regression this guards is a first-boot failure: the CA root certificate is
// stored under `certs/<CA common name>.pem`, and a common name with spaces
// ("QuicBaaS Root CA") made the permission chmod target a path that does not
// exist.
var escapableKeyCases = []struct {
	name     string
	key      string
	wantPerm fs.FileMode
}{
	{name: "certs spaces in filename", key: "certs/QuicBaaS Root CA.pem", wantPerm: certsFilePerms},
	{name: "certs spaces in directory", key: "certs/QuicBaaS Root CA/root.pem", wantPerm: certsFilePerms},
	{name: "certs percent", key: "certs/100%25 valid.pem", wantPerm: certsFilePerms},
	{name: "certs plus", key: "certs/root+intermediate.pem", wantPerm: certsFilePerms},
	{name: "certs unicode", key: "certs/café-räksmörgås.pem", wantPerm: certsFilePerms},
	{name: "certs leading dot segment", key: "certs/.hidden.pem", wantPerm: certsFilePerms},
	{name: "certs tab", key: "certs/tab\there.pem", wantPerm: certsFilePerms},
	{name: "certs plain", key: "certs/root.pem", wantPerm: certsFilePerms},
	{name: "keys spaces", key: "keys/My Signing Key.pem", wantPerm: keysFilePerms},
	{name: "keys plain", key: "keys/signing.pem", wantPerm: keysFilePerms},
	{name: "no prefix spaces", key: "QuicBaaS Root CA.pem", wantPerm: defaultPerms},
	{name: "no prefix plain", key: "root.pem", wantPerm: defaultPerms},
	{name: "unwidened prefix spaces", key: "blobs/My Blob.bin", wantPerm: defaultPerms},
}

// soleStoredFile returns the path of the only regular file beneath root. Tests
// use a store per case, so the engine leaves exactly one file behind; locating
// it by walking rather than by recomputing the escaped name keeps the
// assertion independent of the code under test.
//
// The store's own cross-process lock file (lock.go's lockFileName) is
// excluded: it is not a key the engine wrote, never touched by Get/Put/List,
// and Put's first call is exactly what creates it, so a walk that counted it
// would see two files after the very first write this package makes.
func soleStoredFile(t *testing.T, root string) string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() != lockFileName {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir(%q) error = %v", root, err)
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one stored file under %q, found %d: %v", root, len(found), found)
	}
	return found[0]
}

// TestPutEscapedKeyPermissions verifies Put applies the prefix-based
// permissions to the file the engine actually wrote, including for keys the
// engine percent-escapes on disk.
func TestPutEscapedKeyPermissions(t *testing.T) {
	ctx := context.Background()
	value := []byte("payload")

	for _, tc := range escapableKeyCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupTestDir(t)
			store, err := New(dir)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() { _ = store.Close() }()

			if err := store.Put(ctx, tc.key, value); err != nil {
				t.Fatalf("Put(%q) error = %v", tc.key, err)
			}

			got, err := store.Get(ctx, tc.key)
			if err != nil {
				t.Fatalf("Get(%q) error = %v", tc.key, err)
			}
			if !bytes.Equal(got, value) {
				t.Errorf("Get(%q) = %q, want %q", tc.key, got, value)
			}

			path := soleStoredFile(t, dir)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("Stat(%q) error = %v", path, err)
			}
			if perm := info.Mode().Perm(); perm != tc.wantPerm {
				t.Errorf("permissions of %q = %o, want %o", path, perm, tc.wantPerm)
			}
		})
	}
}

// TestPutIfAbsentEscapedKeyPermissions verifies PutIfAbsent widens permissions
// on the same escaped on-disk path Put does.
func TestPutIfAbsentEscapedKeyPermissions(t *testing.T) {
	ctx := context.Background()
	value := []byte("payload")

	for _, tc := range escapableKeyCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupTestDir(t)
			store, err := New(dir)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() { _ = store.Close() }()

			stored, err := store.PutIfAbsent(ctx, tc.key, value)
			if err != nil {
				t.Fatalf("PutIfAbsent(%q) error = %v", tc.key, err)
			}
			if !stored {
				t.Fatalf("PutIfAbsent(%q) on a fresh key = false, want true", tc.key)
			}

			path := soleStoredFile(t, dir)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("Stat(%q) error = %v", path, err)
			}
			if perm := info.Mode().Perm(); perm != tc.wantPerm {
				t.Errorf("permissions of %q = %o, want %o", path, perm, tc.wantPerm)
			}
		})
	}
}

// TestKeyPathMatchesEngineLayout is the anti-drift guard for the mirrored
// go-qrdb path encoding: for every key shape it writes through the real engine
// and asserts keyPath resolves to the file the engine actually created. If
// go-qrdb ever changes its key-to-path codec, this test fails instead of the
// chmod silently targeting a nonexistent path at first boot.
func TestKeyPathMatchesEngineLayout(t *testing.T) {
	ctx := context.Background()
	value := []byte("payload")

	for _, tc := range escapableKeyCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupTestDir(t)
			store, err := New(dir)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() { _ = store.Close() }()

			if err := store.Put(ctx, tc.key, value); err != nil {
				t.Fatalf("Put(%q) error = %v", tc.key, err)
			}

			fileStore, ok := store.(*FileStorage)
			if !ok {
				t.Fatalf("New() returned %T, want *FileStorage", store)
			}
			if got, want := fileStore.keyPath(tc.key), soleStoredFile(t, dir); got != want {
				t.Errorf("keyPath(%q) = %q, want the engine's path %q", tc.key, got, want)
			}
		})
	}
}

// TestEncodeKeyToPath pins the encoding itself, byte for byte.
func TestEncodeKeyToPath(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{name: "plain", key: "certs/root.pem", want: "certs/root.pem"},
		{name: "space", key: "certs/QuicBaaS Root CA.pem", want: "certs/QuicBaaS%20Root%20CA.pem"},
		{name: "space in directory", key: "certs/Root CA/leaf.pem", want: "certs/Root%20CA/leaf.pem"},
		{name: "percent is escaped", key: "certs/100%.pem", want: "certs/100%25.pem"},
		{name: "plus passes through", key: "certs/a+b.pem", want: "certs/a+b.pem"},
		{name: "unicode", key: "certs/café.pem", want: "certs/caf%C3%A9.pem"},
		{name: "tab", key: "a\tb", want: "a%09b"},
		{name: "leading dot escaped per segment", key: ".a/.b/c.d", want: "%2Ea/%2Eb/c.d"},
		{name: "interior dot kept", key: "a.b/c.d", want: "a.b/c.d"},
		{name: "empty", key: "", want: ""},
		{name: "separators preserved", key: "a/b/c", want: "a/b/c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodeKeyToPath(tt.key); got != tt.want {
				t.Errorf("encodeKeyToPath(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}
