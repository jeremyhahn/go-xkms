// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)
// for non-commercial use. Commercial licenses are available.
// See LICENSE and LICENSE-COMMERCIAL for details.

package bootstrap

import (
	"testing"

	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
	"github.com/stretchr/testify/require"
)

// TestNoiseServerSentinels_AreTheUpstreamValues pins that each re-export IS
// the upstream sentinel, not a copy with the same text: errors.Is on the
// re-export must match what the composed server actually returns.
func TestNoiseServerSentinels_AreTheUpstreamValues(t *testing.T) {
	require.Same(t, noiseboot.ErrShutdownIncomplete, ErrNoiseShutdownIncomplete)
	require.Same(t, noiseboot.ErrServerNotStarted, ErrNoiseServerNotStarted)
	require.Same(t, noiseboot.ErrServerAlreadyStarted, ErrNoiseServerAlreadyStarted)
}

// TestNoiseServerSentinels_AreDistinct guards against two re-exports being
// wired to the same upstream value, which errors.Is could never tell apart.
func TestNoiseServerSentinels_AreDistinct(t *testing.T) {
	require.NotErrorIs(t, ErrNoiseShutdownIncomplete, ErrNoiseServerNotStarted)
	require.NotErrorIs(t, ErrNoiseShutdownIncomplete, ErrNoiseServerAlreadyStarted)
	require.NotErrorIs(t, ErrNoiseServerNotStarted, ErrNoiseServerAlreadyStarted)
}
