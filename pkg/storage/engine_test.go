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

package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbstorage "github.com/jeremyhahn/go-qrdb/sdk/go/storage"
)

// newMemEngineBackend returns an engine-backed Backend over the go-qrdb memory
// engine for fast, host-free adapter tests.
func newMemEngineBackend(t *testing.T) Backend {
	t.Helper()
	return NewEngineBackend(qrdbstorage.NewMemoryStorage())
}

func TestEngineBackendPutGet(t *testing.T) {
	ctx := context.Background()
	b := newMemEngineBackend(t)
	t.Cleanup(func() { _ = b.Close() })

	if err := b.Put(ctx, "keys/alice", []byte("secret")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Get(ctx, "keys/alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "secret" {
		t.Fatalf("Get = %q, want %q", got, "secret")
	}
}

func TestEngineBackendGetMissingReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	b := newMemEngineBackend(t)
	t.Cleanup(func() { _ = b.Close() })

	_, err := b.Get(ctx, "absent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(absent) error = %v, want ErrNotFound", err)
	}
}

func TestEngineBackendDeleteMissingReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	b := newMemEngineBackend(t)
	t.Cleanup(func() { _ = b.Close() })

	if err := b.Delete(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete(absent) = %v, want ErrNotFound", err)
	}
}

func TestEngineBackendDelete(t *testing.T) {
	ctx := context.Background()
	b := newMemEngineBackend(t)
	t.Cleanup(func() { _ = b.Close() })

	if err := b.Put(ctx, "k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := b.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if ok, _ := b.Exists(ctx, "k"); ok {
		t.Fatalf("Exists after Delete = true, want false")
	}
}

func TestEngineBackendListSortedAndPrefixed(t *testing.T) {
	ctx := context.Background()
	b := newMemEngineBackend(t)
	t.Cleanup(func() { _ = b.Close() })

	for _, k := range []string{"oath/z", "oath/a", "pw/x"} {
		if err := b.Put(ctx, k, []byte("v")); err != nil {
			t.Fatalf("Put %q: %v", k, err)
		}
	}
	keys, err := b.List(ctx, "oath/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"oath/a", "oath/z"}
	if len(keys) != len(want) || keys[0] != want[0] || keys[1] != want[1] {
		t.Fatalf("List(oath/) = %v, want %v", keys, want)
	}
}

func TestEngineBackendScanVisitsPrefix(t *testing.T) {
	ctx := context.Background()
	b := newMemEngineBackend(t)
	t.Cleanup(func() { _ = b.Close() })

	for _, k := range []string{"a/1", "a/2", "b/1"} {
		_ = b.Put(ctx, k, []byte(k))
	}
	seen := map[string]string{}
	err := b.Scan(ctx, "a/", func(key string, value []byte) error {
		seen[key] = string(value)
		return nil
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(seen) != 2 || seen["a/1"] != "a/1" || seen["a/2"] != "a/2" {
		t.Fatalf("Scan visited %v, want a/1 and a/2", seen)
	}
}

func TestEngineBackendScanStopsOnError(t *testing.T) {
	ctx := context.Background()
	b := newMemEngineBackend(t)
	t.Cleanup(func() { _ = b.Close() })

	for _, k := range []string{"a/1", "a/2", "a/3"} {
		_ = b.Put(ctx, k, []byte("v"))
	}
	stop := errors.New("stop")
	count := 0
	err := b.Scan(ctx, "a/", func(string, []byte) error {
		count++
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("Scan error = %v, want stop", err)
	}
	if count != 1 {
		t.Fatalf("Scan invoked fn %d times, want 1 (early stop)", count)
	}
}

func TestEngineBackendClosedReturnsErrClosed(t *testing.T) {
	ctx := context.Background()
	b := newMemEngineBackend(t)
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Every operation against the closed engine must map the engine's
	// closed-error onto the ErrClosed sentinel (the Backend contract), not a
	// wrapped EngineError.
	if _, err := b.Get(ctx, "k"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Get after Close = %v, want ErrClosed", err)
	}
	if err := b.Put(ctx, "k", []byte("v")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Put after Close = %v, want ErrClosed", err)
	}
	if err := b.Delete(ctx, "k"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Delete after Close = %v, want ErrClosed", err)
	}
	if _, err := b.List(ctx, ""); !errors.Is(err, ErrClosed) {
		t.Fatalf("List after Close = %v, want ErrClosed", err)
	}
	if _, err := b.Exists(ctx, "k"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Exists after Close = %v, want ErrClosed", err)
	}
}

// TestEngineBackendWrapsNonClosedError verifies that a genuine, non-closed
// engine failure (here: an empty key, which the engine rejects) surfaces as an
// *EngineError carrying the operation/key and unwrapping to the engine error.
func TestEngineBackendWrapsNonClosedError(t *testing.T) {
	ctx := context.Background()
	b := newMemEngineBackend(t)
	t.Cleanup(func() { _ = b.Close() })

	_, err := b.Get(ctx, "")
	var ee *EngineError
	if !errors.As(err, &ee) {
		t.Fatalf("Get(empty key) = %v, want *EngineError", err)
	}
	if ee.Op != "get" || ee.Unwrap() == nil {
		t.Fatalf("EngineError = %+v, want op=get with wrapped err", ee)
	}
	if err := b.Put(ctx, "", []byte("v")); !errors.As(err, &ee) {
		t.Fatalf("Put(empty key) = %v, want *EngineError", err)
	}
}

func TestEngineErrorMessage(t *testing.T) {
	withKey := &EngineError{Op: "get", Key: "k", Err: errors.New("boom")}
	if withKey.Error() == "" || withKey.Unwrap() == nil {
		t.Fatalf("EngineError with key formatted incorrectly: %q", withKey.Error())
	}
	noKey := &EngineError{Op: "close", Err: errors.New("boom")}
	if noKey.Error() == "" {
		t.Fatalf("EngineError without key formatted incorrectly")
	}
}

func TestOpenEngineMemory(t *testing.T) {
	ctx := context.Background()
	b, err := OpenEngine(EngineConfig{Kind: EngineMemory})
	if err != nil {
		t.Fatalf("OpenEngine(memory): %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.Put(ctx, "k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got, _ := b.Get(ctx, "k"); string(got) != "v" {
		t.Fatalf("Get = %q, want v", got)
	}
}

// TestOpenEngineFileHashedLayout checks that the file engine persists a record
// across a reopen and stores it under go-qrdb's hashed layout (go-qrdb#592):
// the key's '/' segments never become directories under the root.
func TestOpenEngineFileHashedLayout(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	b, err := OpenEngine(EngineConfig{Kind: EngineFile, Path: dir})
	if err != nil {
		t.Fatalf("OpenEngine(file): %v", err)
	}
	if err := b.Put(ctx, "staticpw/alice", []byte("secret")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "staticpw")); !os.IsNotExist(err) {
		t.Fatalf("key segment became a directory under the root (stat err = %v)", err)
	}

	reopened := openFileEngine(t, dir)
	got, err := reopened.Get(ctx, "staticpw/alice")
	if err != nil || string(got) != "secret" {
		t.Fatalf("Get after reopen = %q, %v; want secret", got, err)
	}
}

func TestOpenEngineEmptyKindDefaultsToFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	b, err := OpenEngine(EngineConfig{Path: dir})
	if err != nil {
		t.Fatalf("OpenEngine(empty kind): %v", err)
	}
	if err := b.Put(ctx, "k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Only a file engine's directory reopens as one and still holds the record.
	reopened := openFileEngine(t, dir)
	if got, err := reopened.Get(ctx, "k"); err != nil || string(got) != "v" {
		t.Fatalf("empty kind did not default to file engine: Get = %q, %v", got, err)
	}
}

// openFileEngine reopens dir as a file engine, closed when the test ends.
func openFileEngine(t *testing.T, dir string) Backend {
	t.Helper()
	b, err := OpenEngine(EngineConfig{Kind: EngineFile, Path: dir})
	if err != nil {
		t.Fatalf("reopen file engine: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestOpenEnginePebble(t *testing.T) {
	ctx := context.Background()
	b, err := OpenEngine(EngineConfig{Kind: EnginePebble, Path: t.TempDir()})
	if err != nil {
		t.Fatalf("OpenEngine(pebble): %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.Put(ctx, "k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got, _ := b.Get(ctx, "k"); string(got) != "v" {
		t.Fatalf("Get = %q, want v", got)
	}
}

func TestOpenEngineMissingPath(t *testing.T) {
	for _, kind := range []EngineKind{EngineFile, EnginePebble} {
		if _, err := OpenEngine(EngineConfig{Kind: kind}); !errors.Is(err, ErrEnginePathRequired) {
			t.Fatalf("OpenEngine(%s, no path) = %v, want ErrEnginePathRequired", kind, err)
		}
	}
}

func TestOpenEngineUnknownKind(t *testing.T) {
	if _, err := OpenEngine(EngineConfig{Kind: "bogus", Path: t.TempDir()}); !errors.Is(err, ErrUnknownEngine) {
		t.Fatalf("OpenEngine(bogus) = %v, want ErrUnknownEngine", err)
	}
}
