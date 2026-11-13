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

// TestValidateStorageKeyAcceptsCleanKeys verifies that simple, nested and
// dotted keys, and keys whose trailing ".." cleans to a name inside the root,
// are accepted.
func TestValidateStorageKeyAcceptsCleanKeys(t *testing.T) {
	for _, key := range []string{"my-key", "keys/alice/signing", "certs/server.pem", "foo/bar/..", "foo/.."} {
		assert.NoError(t, validateStorageKey(key), "validateStorageKey(%q)", key)
	}
}

// TestPublicAPIRejectsInvalidKeys verifies that empty, NUL-byte, absolute and
// traversal keys are rejected by every key-accepting method (the engine itself
// does not block traversal, so the file backend must).
func TestPublicAPIRejectsInvalidKeys(t *testing.T) {
	ctx := context.Background()
	store, err := New(t.TempDir())
	assert.NoError(t, err)
	defer store.Close()

	badKeys := map[string]string{
		"":                        "cannot be empty",
		"test\x00key":             "null byte",
		"/etc/passwd":             "absolute path",
		"../secret":               "path traversal",
		"foo/../../../etc/passwd": "path traversal",
	}
	for badKey, wantMsg := range badKeys {
		putErr := store.Put(ctx, badKey, []byte("v"))
		if assert.Error(t, putErr, "Put(%q) should be rejected", badKey) {
			assert.Contains(t, putErr.Error(), wantMsg, "Put(%q)", badKey)
		}
		_, getErr := store.Get(ctx, badKey)
		assert.Error(t, getErr, "Get(%q) should be rejected", badKey)
		assert.Error(t, store.Delete(ctx, badKey), "Delete(%q) should be rejected", badKey)
		_, existsErr := store.Exists(ctx, badKey)
		assert.Error(t, existsErr, "Exists(%q) should be rejected", badKey)
	}
}
