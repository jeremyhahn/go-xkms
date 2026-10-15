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

package testutil

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMutualTLSState proves the state is what an mTLS caller presents: a
// completed TLS 1.3 handshake with the client's verified chain and an
// exporter that still answers after the pipe is closed.
func TestMutualTLSState(t *testing.T) {
	state, err := MutualTLSState()
	require.NoError(t, err)

	assert.True(t, state.HandshakeComplete)
	assert.Equal(t, uint16(tls.VersionTLS13), state.Version)
	require.NotEmpty(t, state.VerifiedChains)
	assert.Equal(t, "peer", state.VerifiedChains[0][0].Subject.CommonName)

	material, err := state.ExportKeyingMaterial("EXPORTER-test", nil, 32)
	require.NoError(t, err)
	assert.Len(t, material, 32)
}

// TestMutualTLSState_FreshIdentityPerCall proves each call mints its own CA
// and client certificate, so tests calling it never share a peer.
func TestMutualTLSState_FreshIdentityPerCall(t *testing.T) {
	first, err := MutualTLSState()
	require.NoError(t, err)
	second, err := MutualTLSState()
	require.NoError(t, err)
	assert.NotEqual(t, first.PeerCertificates[0].Raw, second.PeerCertificates[0].Raw)
}
