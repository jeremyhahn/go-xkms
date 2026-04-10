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

package store

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBlobStoreCreateError verifies the Error and Unwrap methods on
// BlobStoreCreateError.
func TestBlobStoreCreateError(t *testing.T) {
	cause := errors.New("permission denied")
	err := &BlobStoreCreateError{Cause: cause}

	assert.Equal(t, "blob store: failed to create: permission denied", err.Error())
	assert.Equal(t, cause, err.Unwrap())
	require.ErrorIs(t, err, cause)
}

// TestBlobReadError verifies the Error and Unwrap methods on BlobReadError.
func TestBlobReadError(t *testing.T) {
	cause := errors.New("file not found")
	err := &BlobReadError{Name: "key.bin", Cause: cause}

	assert.Equal(t, "blob store: failed to read key.bin: file not found", err.Error())
	assert.Equal(t, cause, err.Unwrap())
	require.ErrorIs(t, err, cause)
}

// TestBlobWriteError verifies the Error and Unwrap methods on BlobWriteError.
func TestBlobWriteError(t *testing.T) {
	cause := errors.New("disk full")
	err := &BlobWriteError{Name: "cert.pem", Cause: cause}

	assert.Equal(t, "blob store: failed to write cert.pem: disk full", err.Error())
	assert.Equal(t, cause, err.Unwrap())
	require.ErrorIs(t, err, cause)
}

// TestBlobDeleteError verifies the Error and Unwrap methods on BlobDeleteError.
func TestBlobDeleteError(t *testing.T) {
	cause := errors.New("operation not permitted")
	err := &BlobDeleteError{Name: "old-key.bin", Cause: cause}

	assert.Equal(t, "blob store: failed to delete old-key.bin: operation not permitted", err.Error())
	assert.Equal(t, cause, err.Unwrap())
	require.ErrorIs(t, err, cause)
}
