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
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestScan_WithPrefix verifies that Scan returns only entries matching the given prefix.
func TestScan_WithPrefix(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	entries := map[string][]byte{
		"users/alice": []byte("alice-data"),
		"users/bob":   []byte("bob-data"),
		"config/db":   []byte("db-config"),
		"config/app":  []byte("app-config"),
		"standalone":  []byte("standalone-data"),
	}
	for k, v := range entries {
		if err := store.Put(ctx, k, v); err != nil {
			t.Fatalf("Put(%s) error = %v", k, err)
		}
	}

	result := make(map[string][]byte)
	err = store.Scan(ctx, "users/", func(key string, value []byte) error {
		result[key] = value
		return nil
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Scan(users/) returned %d entries, want 2", len(result))
	}
	for _, key := range []string{"users/alice", "users/bob"} {
		val, ok := result[key]
		if !ok {
			t.Errorf("Scan() missing expected key %q", key)
			continue
		}
		if string(val) != string(entries[key]) {
			t.Errorf("Scan() key %q value = %q, want %q", key, val, entries[key])
		}
	}

	// Ensure keys from other prefixes are absent.
	for _, key := range []string{"config/db", "config/app", "standalone"} {
		if _, ok := result[key]; ok {
			t.Errorf("Scan(users/) should not include key %q", key)
		}
	}
}

// TestScan_EmptyPrefix verifies that Scan with an empty prefix returns all entries.
func TestScan_EmptyPrefix(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	entries := map[string][]byte{
		"alpha": []byte("a"),
		"beta":  []byte("b"),
		"gamma": []byte("c"),
	}
	for k, v := range entries {
		if err := store.Put(ctx, k, v); err != nil {
			t.Fatalf("Put(%s) error = %v", k, err)
		}
	}

	result := make(map[string][]byte)
	err = store.Scan(ctx, "", func(key string, value []byte) error {
		result[key] = value
		return nil
	})
	if err != nil {
		t.Fatalf("Scan(\"\") error = %v", err)
	}

	if len(result) != len(entries) {
		t.Errorf("Scan(\"\") returned %d entries, want %d", len(result), len(entries))
	}
	for k, want := range entries {
		got, ok := result[k]
		if !ok {
			t.Errorf("Scan(\"\") missing key %q", k)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("Scan(\"\") key %q = %q, want %q", k, got, want)
		}
	}
}

// TestScan_EmptyStore verifies that Scan on an empty store returns an empty map (not nil).
func TestScan_EmptyStore(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	result := make(map[string][]byte)
	err = store.Scan(ctx, "", func(key string, value []byte) error {
		result[key] = value
		return nil
	})
	if err != nil {
		t.Fatalf("Scan() on empty store error = %v", err)
	}
	if len(result) != 0 {
		t.Errorf("Scan() on empty store returned %d entries, want 0", len(result))
	}
}

// TestScan_NoMatchingPrefix verifies Scan returns empty map when prefix matches nothing.
func TestScan_NoMatchingPrefix(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Put(ctx, "keys/rsa", []byte("rsa-key")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	result := make(map[string][]byte)
	err = store.Scan(ctx, "nonexistent/", func(key string, value []byte) error {
		result[key] = value
		return nil
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(result) != 0 {
		t.Errorf("Scan(nonexistent/) returned %d entries, want 0", len(result))
	}
}

// TestScan_ValuesAreCorrect verifies the values returned by Scan match what was stored.
func TestScan_ValuesAreCorrect(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// Store binary data to verify byte-for-byte accuracy.
	binaryVal := []byte{0x00, 0x01, 0x02, 0xFE, 0xFF}
	if err := store.Put(ctx, "keys/binary", binaryVal); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	result := make(map[string][]byte)
	err = store.Scan(ctx, "keys/", func(key string, value []byte) error {
		result[key] = value
		return nil
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	got, ok := result["keys/binary"]
	if !ok {
		t.Fatal("Scan() missing key keys/binary")
	}
	if len(got) != len(binaryVal) {
		t.Fatalf("Scan() value length = %d, want %d", len(got), len(binaryVal))
	}
	for i, b := range binaryVal {
		if got[i] != b {
			t.Errorf("Scan() value[%d] = %x, want %x", i, got[i], b)
		}
	}
}

// TestScan_WalkError verifies Scan returns an error when the directory is inaccessible.
func TestScan_WalkError(t *testing.T) {
	skipIfRoot(t)

	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Put(ctx, "keys/secret", []byte("data")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Create a subdirectory and make it inaccessible so WalkDir returns an error.
	badDir := filepath.Join(dir, "locked")
	if err := os.MkdirAll(badDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Chmod(badDir, 0000); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer func() { _ = os.Chmod(badDir, 0700) }()

	err = store.Scan(ctx, "", func(_ string, _ []byte) error { return nil })
	if err == nil {
		t.Error("Scan() with inaccessible directory should return error")
	}
}

// TestScan_ReadFileError verifies Scan returns an error when a file cannot be read.
func TestScan_ReadFileError(t *testing.T) {
	skipIfRoot(t)

	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	key := "keys/unreadable"
	if err := store.Put(ctx, key, []byte("secret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Remove read permission on the file itself.
	filePath := filepath.Join(dir, key)
	if err := os.Chmod(filePath, 0000); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer func() { _ = os.Chmod(filePath, 0600) }()

	err = store.Scan(ctx, "", func(_ string, _ []byte) error { return nil })
	if err == nil {
		t.Error("Scan() with unreadable file should return error")
	}
}

// TestScan_MultipleKeysWithSamePathDepth ensures Scan handles flat and nested keys together.
func TestScan_MultipleKeysWithSamePathDepth(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	entries := map[string][]byte{
		"keys/ec/p256":  []byte("ec-p256"),
		"keys/ec/p384":  []byte("ec-p384"),
		"keys/rsa/2048": []byte("rsa-2048"),
		"certs/server":  []byte("server-cert"),
	}
	for k, v := range entries {
		if err := store.Put(ctx, k, v); err != nil {
			t.Fatalf("Put(%s) error = %v", k, err)
		}
	}

	// Scan keys/ec/ prefix only.
	result := make(map[string][]byte)
	err = store.Scan(ctx, "keys/ec/", func(key string, value []byte) error {
		result[key] = value
		return nil
	})
	if err != nil {
		t.Fatalf("Scan(keys/ec/) error = %v", err)
	}
	if len(result) != 2 {
		t.Errorf("Scan(keys/ec/) returned %d entries, want 2", len(result))
	}
	for _, key := range []string{"keys/ec/p256", "keys/ec/p384"} {
		if _, ok := result[key]; !ok {
			t.Errorf("Scan() missing key %q", key)
		}
	}
}
