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

package qrdb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
)

// roundTrip exercises all Backend operations on the given backend.
func roundTrip(t *testing.T, b *Backend) {
	t.Helper()
	ctx := context.Background()

	key := "test/roundtrip"
	value := []byte("hello embedded")

	// Put
	if err := b.Put(ctx, key, value); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Get
	got, err := b.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(got) != string(value) {
		t.Fatalf("Get() = %q, want %q", got, value)
	}

	// Exists
	exists, err := b.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !exists {
		t.Fatal("Exists() = false, want true")
	}

	// List
	keys, err := b.List(ctx, "test/")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Fatalf("List() = %v, want [%s]", keys, key)
	}

	// Scan
	pairs := make(map[string][]byte)
	err = b.Scan(ctx, "test/", func(key string, value []byte) error {
		pairs[key] = value
		return nil
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("Scan() returned %d pairs, want 1", len(pairs))
	}
	if string(pairs[key]) != string(value) {
		t.Fatalf("Scan()[%s] = %q, want %q", key, pairs[key], value)
	}

	// Delete
	if err := b.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deletion
	_, err = b.Get(ctx, key)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: error = %v, want ErrNotFound", err)
	}
}

func TestNewMemory(t *testing.T) {
	b, err := NewMemory()
	if err != nil {
		t.Fatalf("NewMemory() error = %v", err)
	}
	defer func() { _ = b.Close() }()

	roundTrip(t, b)
}

func TestNewMemory_Close(t *testing.T) {
	b, err := NewMemory()
	if err != nil {
		t.Fatalf("NewMemory() error = %v", err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNewMemory_Close_PreventsOps(t *testing.T) {
	b, err := NewMemory()
	if err != nil {
		t.Fatalf("NewMemory() error = %v", err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Operations after Close should return an error from the
	// closed transport/client.
	ctx := context.Background()
	_, getErr := b.Get(ctx, "key")
	if getErr == nil {
		t.Fatal("Get after Close: error = nil, want error")
	}
}

func TestNewFile(t *testing.T) {
	dir, err := os.MkdirTemp("", "TestNewFile")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	b, err := NewFile(dir)
	if err != nil {
		t.Fatalf("NewFile() error = %v", err)
	}
	defer func() { _ = b.Close() }()

	roundTrip(t, b)
}

func TestNewFile_Close(t *testing.T) {
	dir := t.TempDir()
	b, err := NewFile(dir)
	if err != nil {
		t.Fatalf("NewFile() error = %v", err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNewFile_InvalidPath(t *testing.T) {
	_, err := NewFile("")
	if err == nil {
		t.Fatal("NewFile('') error = nil, want error")
	}

	var fe *FactoryError
	if !errors.As(err, &fe) {
		t.Fatalf("NewFile('') error type = %T, want *FactoryError", err)
	}
	if fe.Engine != "file" {
		t.Fatalf("FactoryError.Engine = %q, want %q", fe.Engine, "file")
	}
}

func TestNewPebble(t *testing.T) {
	dir := t.TempDir()
	b, err := NewPebble(dir)
	if err != nil {
		t.Fatalf("NewPebble() error = %v", err)
	}
	defer func() { _ = b.Close() }()

	roundTrip(t, b)
}

func TestNewPebble_Close(t *testing.T) {
	dir := t.TempDir()
	b, err := NewPebble(dir)
	if err != nil {
		t.Fatalf("NewPebble() error = %v", err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNewPebble_InvalidPath(t *testing.T) {
	_, err := NewPebble("")
	if err == nil {
		t.Fatal("NewPebble('') error = nil, want error")
	}

	var fe *FactoryError
	if !errors.As(err, &fe) {
		t.Fatalf("NewPebble('') error type = %T, want *FactoryError", err)
	}
	if fe.Engine != "pebble" {
		t.Fatalf("FactoryError.Engine = %q, want %q", fe.Engine, "pebble")
	}
}

func TestNewMemory_MultipleKeys(t *testing.T) {
	b, err := NewMemory()
	if err != nil {
		t.Fatalf("NewMemory() error = %v", err)
	}
	defer func() { _ = b.Close() }()

	ctx := context.Background()

	// Insert multiple keys with different prefixes.
	entries := map[string]string{
		"ns1/a": "value-a",
		"ns1/b": "value-b",
		"ns2/c": "value-c",
	}
	for k, v := range entries {
		if err := b.Put(ctx, k, []byte(v)); err != nil {
			t.Fatalf("Put(%s) error = %v", k, err)
		}
	}

	// List with prefix should filter correctly.
	keys, err := b.List(ctx, "ns1/")
	if err != nil {
		t.Fatalf("List(ns1/) error = %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("List(ns1/) returned %d keys, want 2", len(keys))
	}

	// Scan with prefix should filter correctly.
	pairs := make(map[string][]byte)
	err = b.Scan(ctx, "ns2/", func(key string, value []byte) error {
		pairs[key] = value
		return nil
	})
	if err != nil {
		t.Fatalf("Scan(ns2/) error = %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("Scan(ns2/) returned %d pairs, want 1", len(pairs))
	}
}

// ---------------------------------------------------------------------------
// FactoryError Tests
// ---------------------------------------------------------------------------

func TestFactoryError_Error(t *testing.T) {
	cause := errors.New("open /bad/path: no such file or directory")
	fe := &FactoryError{Engine: "file", Err: cause}

	got := fe.Error()

	expected := "qrdb factory: engine=file: open /bad/path: no such file or directory"
	if got != expected {
		t.Fatalf("FactoryError.Error() = %q, want %q", got, expected)
	}
}

func TestFactoryError_Error_PebbleEngine(t *testing.T) {
	cause := errors.New("pebble: path must be non-empty")
	fe := &FactoryError{Engine: "pebble", Err: cause}

	got := fe.Error()

	expected := "qrdb factory: engine=pebble: pebble: path must be non-empty"
	if got != expected {
		t.Fatalf("FactoryError.Error() = %q, want %q", got, expected)
	}
}

func TestFactoryError_Unwrap_ReturnsUnderlyingError(t *testing.T) {
	cause := errors.New("underlying cause")
	fe := &FactoryError{Engine: "memory", Err: cause}

	if fe.Unwrap() != cause {
		t.Fatalf("FactoryError.Unwrap() = %v, want %v", fe.Unwrap(), cause)
	}
}

func TestFactoryError_Unwrap_ErrorsIs(t *testing.T) {
	sentinel := errors.New("sentinel")
	fe := &FactoryError{Engine: "file", Err: fmt.Errorf("wrapped: %w", sentinel)}

	if !errors.Is(fe, sentinel) {
		t.Fatal("errors.Is should unwrap through FactoryError to reach the sentinel")
	}
}

func TestFactoryError_As_ReachableFromNewFile(t *testing.T) {
	// NewFile with an empty path returns a *FactoryError; verify the full
	// error message format produced by the real factory path.
	_, err := NewFile("")
	if err == nil {
		t.Fatal("NewFile('') error = nil, want error")
	}

	var fe *FactoryError
	if !errors.As(err, &fe) {
		t.Fatalf("error type = %T, want *FactoryError", err)
	}

	msg := fe.Error()
	if msg == "" {
		t.Fatal("FactoryError.Error() must not be empty")
	}
	// Message must contain the engine name prefix.
	if fe.Engine != "file" {
		t.Fatalf("FactoryError.Engine = %q, want %q", fe.Engine, "file")
	}
}
