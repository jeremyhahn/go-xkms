// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package file

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ========================================================================
// Test validateStorageKey
// ========================================================================

func TestValidateStorageKey_EmptyKey(t *testing.T) {
	err := validateStorageKey("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestValidateStorageKey_NullByte(t *testing.T) {
	err := validateStorageKey("test\x00key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "null byte")
}

func TestValidateStorageKey_AbsolutePath(t *testing.T) {
	err := validateStorageKey("/etc/passwd")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "absolute path")
}

func TestValidateStorageKey_PathTraversalAtStart(t *testing.T) {
	err := validateStorageKey("../secret")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "path traversal")
}

func TestValidateStorageKey_PathTraversalInMiddle(t *testing.T) {
	err := validateStorageKey("foo/../../../etc/passwd")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "path traversal")
}

func TestValidateStorageKey_ValidDotDotAtEnd(t *testing.T) {
	// "foo/bar/.." is cleaned to "foo" which is valid
	err := validateStorageKey("foo/bar/..")
	assert.NoError(t, err)
}

func TestValidateStorageKey_ValidSimpleKey(t *testing.T) {
	err := validateStorageKey("my-key")
	assert.NoError(t, err)
}

func TestValidateStorageKey_ValidNestedKey(t *testing.T) {
	err := validateStorageKey("keys/alice/signing")
	assert.NoError(t, err)
}

func TestValidateStorageKey_ValidWithDots(t *testing.T) {
	// Keys like "file.pem" should be valid
	err := validateStorageKey("certs/server.pem")
	assert.NoError(t, err)
}

// ========================================================================
// Test that invalid keys are rejected through the public Backend API
// ========================================================================

// TestPublicAPIRejectsInvalidKeys verifies that traversal/empty/absolute keys
// are rejected by every key-accepting method (the engine itself does not block
// traversal, so the file backend must).
func TestPublicAPIRejectsInvalidKeys(t *testing.T) {
	ctx := context.Background()
	store, err := New(t.TempDir())
	assert.NoError(t, err)
	defer store.Close()

	for _, badKey := range []string{"", "../secret", "a/../../etc/passwd"} {
		assert.Error(t, store.Put(ctx, badKey, []byte("v")), "Put(%q) should be rejected", badKey)
		_, getErr := store.Get(ctx, badKey)
		assert.Error(t, getErr, "Get(%q) should be rejected", badKey)
		assert.Error(t, store.Delete(ctx, badKey), "Delete(%q) should be rejected", badKey)
		_, existsErr := store.Exists(ctx, badKey)
		assert.Error(t, existsErr, "Exists(%q) should be rejected", badKey)
	}
}
