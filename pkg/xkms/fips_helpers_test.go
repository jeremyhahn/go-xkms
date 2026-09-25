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

package xkms

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// requireGCMWrapRefusedForCallerNonce proves that this package's own
// AES-GCM wrap path refuses a caller-supplied nonce under
// GODEBUG=fips140=only, on a disposable fixture independent of whatever
// fixture the calling test was about to build. It exists so a test whose
// whole premise is caller-nonce semantics (nonce reuse, aliasing, and so
// on -- inherently untestable in that mode, since the wrap itself never
// succeeds) still asserts the refusal instead of silently doing nothing.
func requireGCMWrapRefusedForCallerNonce(t *testing.T) {
	t.Helper()
	store, attrs := newUntrackedAESWrappingBackend(t, "fips-probe-be", "fips-probe-kek")
	_, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESGCM),
		gcmParams(uniqueWrapIV(t)), []byte("fips-probe-target-32-bytes-key!!"))
	require.Error(t, err, "a caller-supplied AES-GCM nonce requires the arbitrary-IV construction, "+
		"which GODEBUG=fips140=only refuses")
}
