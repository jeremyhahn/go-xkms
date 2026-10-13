// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package tpmblobtest builds in-memory TPM blob stores for tests of the
// packages above pkg/tpm2/store.
package tpmblobtest

import (
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
)

// New returns the system tenant's BlobStore over a fresh in-memory go-qrdb
// KV store, so each call is isolated from every other.
func New(tb testing.TB) *store.BlobStore {
	tb.Helper()
	blobs, err := store.NewBlobStore(slog.New(slog.NewTextHandler(io.Discard, nil)), testutil.NewMemoryDAOFactory())
	if err != nil {
		tb.Fatalf("tpmblobtest: new blob store: %v", err)
	}
	return blobs
}
