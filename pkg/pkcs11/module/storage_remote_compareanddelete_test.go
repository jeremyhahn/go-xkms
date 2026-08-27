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

package module

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
)

// The remote state backend deliberately does NOT implement
// storage.CompareAndDeleter, and the absence is the contract.
//
// It has no guarded-delete RPC on PKCS11StateClient, and by design no local
// lock: its whole purpose is that several hosts share one server-side token,
// with the server owning atomicity. A locally emulated guard would therefore be
// evaluated nowhere — and this is the ONE backend whose racing writers are
// genuinely in different processes, so a guard that was never evaluated would
// be worth less here than anywhere else. Tracked by #142.
//
// Pinned as a type assertion rather than a comment so that adding a
// CompareAndDelete method to this type — the plausible mistake, since every
// sibling backend has one — fails here instead of silently advertising a
// guarantee the transport cannot keep.
func TestRemoteBackend_DoesNotClaimCompareAndDeleter(t *testing.T) {
	var b storage.Backend = &remoteBackend{}

	_, ok := b.(storage.CompareAndDeleter)
	assert.False(t, ok,
		"the remote state backend must not claim a guarded delete it has no RPC for (#142)")

	// The guarded SWAP is genuinely available, via PKCS11StateCAS, and must stay
	// that way: the two capabilities are independent, and losing the swap would
	// break the multi-client lockout counter.
	assert.Implements(t, (*storage.CompareAndSwapper)(nil), b,
		"the guarded swap has a server-side RPC and remains available")
}
