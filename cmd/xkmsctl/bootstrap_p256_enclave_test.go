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

package main

import (
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/stretchr/testify/require"
)

// TestKeyEnclave_ByteAccess pins the go-enclave v0.11.1 contract the key-file
// path relies on: keyAllocator hands out the process enclave.Allocator, its
// buffers are enclave.ByteAccess, and destroyKeyEnclave releases one.
func TestKeyEnclave_ByteAccess(t *testing.T) {
	var alloc enclave.Allocator
	alloc, err := keyAllocator()
	require.NoError(t, err)

	var buf enclave.ByteAccess
	buf, err = alloc.NewSized(32)
	require.NoError(t, err)
	require.True(t, buf.IsAlive())

	require.NoError(t, destroyKeyEnclave(buf))
	require.False(t, buf.IsAlive(), "buffer still alive after destroyKeyEnclave")
}
