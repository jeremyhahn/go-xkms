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
// and proves what the locker relies on: its coordination client refuses
// the raft-only lease family with the typed capability error, so the
// locker recognises a single-process node from qrdb itself rather than
// from configuration it could be handed wrong.
func TestLockerOnRealStandaloneNode(t *testing.T) {
	coord := barriertest.NewStandaloneCoordinator(t)

	l := newLocker(coord, discardLogger())
	unlock, err := l.lock(context.Background(), "tenant/oidc/shared/x.json")
	require.NoError(t, err)
	unlock()
	assert.True(t, l.standalone.Load(), "a standalone node's lease refusal is recognised")
}
