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
)

// newMemEngineBackend returns an engine-backed Backend over the go-qrdb memory
// engine for fast, host-free adapter tests.
func newMemEngineBackend(t *testing.T) Backend {
	t.Helper()
	return NewEngineBackend(qrdbsdk.NewMemoryStorage())
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

func TestEngineBackendOperationsWrapEngineError(t *testing.T) {
	ctx := context.Background()
	b := newMemEngineBackend(t)
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Every operation against the closed engine must surface an *EngineError
	// that unwraps to the engine's failure.
	_, err := b.Get(ctx, "k")
	var ee *EngineError
	if !errors.As(err, &ee) {
		t.Fatalf("Get after Close error = %v, want *EngineError", err)
	}
	if ee.Op != "get" || ee.Key != "k" || ee.Unwrap() == nil {
		t.Fatalf("EngineError = %+v, want op=get key=k with wrapped err", ee)
	}
	if err := b.Put(ctx, "k", []byte("v")); !errors.As(err, &ee) {
		t.Fatalf("Put after Close error = %v, want *EngineError", err)
	}
	if err := b.Delete(ctx, "k"); !errors.As(err, &ee) {
		t.Fatalf("Delete after Close error = %v, want *EngineError", err)
	}
	if _, err := b.List(ctx, ""); !errors.As(err, &ee) {
		t.Fatalf("List after Close error = %v, want *EngineError", err)
	}
	if _, err := b.Exists(ctx, "k"); !errors.As(err, &ee) {
		t.Fatalf("Exists after Close error = %v, want *EngineError", err)
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

// TestOpenEngineFileFlatLayout is the no-migration regression guard: the file
// engine must write one plain file per key at <path>/<key>, matching xkms's
// historical on-disk format exactly.
func TestOpenEngineFileFlatLayout(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	b, err := OpenEngine(EngineConfig{Kind: EngineFile, Path: dir})
	if err != nil {
		t.Fatalf("OpenEngine(file): %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if err := b.Put(ctx, "staticpw/alice", []byte("secret")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	onDisk := filepath.Join(dir, "staticpw", "alice")
	data, err := os.ReadFile(onDisk)
	if err != nil {
		t.Fatalf("expected flat file at %s: %v", onDisk, err)
	}
	if string(data) != "secret" {
		t.Fatalf("on-disk value = %q, want secret", data)
	}
	// Round-trip through the Backend confirms key↔path symmetry.
	got, err := b.Get(ctx, "staticpw/alice")
	if err != nil || string(got) != "secret" {
		t.Fatalf("Get = %q, %v; want secret", got, err)
	}
}

func TestOpenEngineEmptyKindDefaultsToFile(t *testing.T) {
	dir := t.TempDir()
	b, err := OpenEngine(EngineConfig{Path: dir})
	if err != nil {
		t.Fatalf("OpenEngine(empty kind): %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.Put(context.Background(), "k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "k")); err != nil {
		t.Fatalf("empty kind did not default to file engine: %v", err)
	}
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
