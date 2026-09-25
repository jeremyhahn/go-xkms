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

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestSessionTTLs_NoSessionConfig proves the package defaults are used when
// no session config is set at all.
func TestSessionTTLs_NoSessionConfig(t *testing.T) {
	s := &Server{config: &config.Config{}}
	access, refresh := s.sessionTTLs()
	require.Equal(t, token.DefaultAccessTTL, access)
	require.Equal(t, token.DefaultRefreshTTL, refresh)
}

// TestSessionTTLs_ExplicitDurationsOverrideDefaults proves valid, positive
// configured durations replace the defaults for both access and refresh.
func TestSessionTTLs_ExplicitDurationsOverrideDefaults(t *testing.T) {
	s := &Server{config: &config.Config{
		Auth: config.AuthConfig{Session: &config.SessionConfig{
			AccessTokenTTL:  "5m",
			RefreshTokenTTL: "2h",
		}},
	}}
	access, refresh := s.sessionTTLs()
	require.Equal(t, 5*time.Minute, access)
	require.Equal(t, 2*time.Hour, refresh)
}

// TestSessionTTLs_InvalidOrNonPositiveDurationsFallBackToDefaults proves an
// unparsable or non-positive configured duration is ignored in favor of the
// package default rather than propagating a zero or garbage TTL.
func TestSessionTTLs_InvalidOrNonPositiveDurationsFallBackToDefaults(t *testing.T) {
	s := &Server{config: &config.Config{
		Auth: config.AuthConfig{Session: &config.SessionConfig{
			AccessTokenTTL:  "not-a-duration",
			RefreshTokenTTL: "-1h",
		}},
	}}
	access, refresh := s.sessionTTLs()
	require.Equal(t, token.DefaultAccessTTL, access)
	require.Equal(t, token.DefaultRefreshTTL, refresh)
}

// TestInitializeTokenIssuer_NoDefaultBackendSkips proves the token issuer is
// left unconfigured (not an error) when the default backend was never
// registered, e.g. a composition where backend initialization failed softly
// upstream.
func TestInitializeTokenIssuer_NoDefaultBackendSkips(t *testing.T) {
	s := &Server{
		config:             &config.Config{},
		logger:             custodyQuietLogger(),
		defaultBackendName: "software",
		backends:           map[string]xkms.Backend{},
	}
	require.NoError(t, s.initializeTokenIssuer())
	require.Nil(t, s.tokenIssuer)
}

// TestAllowNodeLocalPlaintextKeys_NodeSealEnabled proves the node seal
// (storage-layer encryption at rest) alone is sufficient to allow plaintext
// key persistence, regardless of the xkms-level barrier config.
func TestAllowNodeLocalPlaintextKeys_NodeSealEnabled(t *testing.T) {
	s := &Server{
		config:          &config.Config{Barrier: config.BarrierConfig{Enabled: true, Strategy: "tpm2"}},
		nodeSealEnabled: true,
	}
	require.True(t, s.allowNodeLocalPlaintextKeys())
}

// TestAllowNodeLocalPlaintextKeys_BarrierEnabledWithoutNodeSeal proves a
// configured, non-"none" barrier that is NOT the node seal refuses plaintext
// persistence, protecting the operator's encryption-at-rest intent.
func TestAllowNodeLocalPlaintextKeys_BarrierEnabledWithoutNodeSeal(t *testing.T) {
	s := &Server{
		config: &config.Config{Barrier: config.BarrierConfig{Enabled: true, Strategy: "passphrase"}},
	}
	require.False(t, s.allowNodeLocalPlaintextKeys())
}
