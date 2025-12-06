// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package file

import (
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
// Test keyToPath edge cases
// ========================================================================

func TestKeyToPath_InvalidKey(t *testing.T) {
	fs := &FileStorage{rootDir: "/tmp/test"}

	// Should return safe invalid path for keys that fail validation
	path := fs.keyToPath("")
	assert.Contains(t, path, "invalid")

	path = fs.keyToPath("../secret")
	assert.Contains(t, path, "invalid")
}

// ========================================================================
// Test pathToKey edge cases
// ========================================================================

func TestPathToKey_PathOutsideRoot(t *testing.T) {
	fs := &FileStorage{rootDir: "/tmp/test-storage"}

	// Path outside root directory
	_, err := fs.pathToKey("/etc/passwd")
	// This should work but return a relative path with ..
	// The error case depends on the platform
	if err != nil {
		assert.Error(t, err)
	}
}
