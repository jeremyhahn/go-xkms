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

package credential

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
)

// TestLockerOnRealStandaloneNode boots a real in-memory standalone qrdb node
// and proves the locker takes a real lease there. Since go-qrdb v0.27 a
// standalone node serves leases with raft mode's semantics, so the locker
// serializes refreshes through qrdb exactly as on a cluster; its
// single-process fallback remains for a backend that refuses leases with the
// typed capability error (covered by the locker's unit tests).
func TestLockerOnRealStandaloneNode(t *testing.T) {
	coord := barriertest.NewStandaloneCoordinator(t)

	l := newLocker(coord, discardLogger())
	unlock, err := l.lock(context.Background(), "tenant/oidc/shared/x.json")
	require.NoError(t, err)
	assert.False(t, l.standalone.Load(), "a standalone node that serves leases is not treated as lease-less")

	// The lease is held: a second locker, standing in for another process,
	// cannot take it until the first releases.
	other := newLocker(coord, discardLogger())
	_, held, err := other.tryAcquire(context.Background(), lockPrefix+hashKey("tenant/oidc/shared/x.json"), lockTTL)
	require.NoError(t, err)
	assert.True(t, held, "the lease excludes a second holder")

	unlock()
	lease, held, err := other.tryAcquire(context.Background(), lockPrefix+hashKey("tenant/oidc/shared/x.json"), lockTTL)
	require.NoError(t, err)
	require.False(t, held, "released, the lease is free")
	require.NotNil(t, lease)
	require.NoError(t, lease.Release(context.Background()))
}
