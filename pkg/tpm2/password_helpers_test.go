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

package tpm2

import (
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// mustPassword builds a types.Password test fixture and destroys it when the
// test ends. Every non-empty password holds an mlocked enclave, so a fixture
// that outlives its test pins locked memory until the process exits; across
// the whole suite those leaks exhaust RLIMIT_MEMLOCK and later allocations
// fail with "secure enclave unavailable". A failed allocation fails the test
// rather than silently falling back to an empty (passwordless) auth value,
// mirroring the production contract enforced by store.NewPassword.
func mustPassword(t testing.TB, b []byte) types.Password {
	t.Helper()
	pw, err := store.NewPassword(b)
	if err != nil {
		t.Fatalf("mustPassword: %v", err)
	}
	t.Cleanup(pw.Clear)
	return pw
}

// lockedBytesInUse reports the locked memory the process allocator has
// admitted, which every password enclave counts against. Comparing it
// around a call shows whether the call released the enclaves it made.
func lockedBytesInUse(t testing.TB) int64 {
	t.Helper()
	alloc, err := enclave.ProcessAllocator()
	if err != nil {
		t.Fatalf("process allocator: %v", err)
	}
	return alloc.InUse()
}
