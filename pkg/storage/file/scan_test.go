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
