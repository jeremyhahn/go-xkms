//go:build tpm_simulator

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestBuildTPM2PlatformSealer_FreshProbeOpensAndEnrolls covers the "no
// pre-injected s.nodeSealTPM" branch of buildTPM2PlatformSealer: with no
// node-seal flip in play, it must probe hardware itself via
// seal.BuildBestStrategy, track the resulting Close under
// s.platformStoreTPMClose, and return a working sealer.
//
// Under the tpm_simulator tag, a bare UseSimulator: true config
// auto-provisions EK, SSRK AND the Platform SRK together as a
// simulator-only test convenience (see pkg/server/platform_store_no_simulator_test.go's
// doc comment on why that file cannot be merged into this one), so the
// fresh probe here always finds an enrolled Platform SRK and succeeds end
// to end -- unlike a real device, which requires a separate enrollment
// ceremony.
func TestBuildTPM2PlatformSealer_FreshProbeOpensAndEnrolls(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Backend: "file", Path: t.TempDir()},
		Backends: config.BackendsConfig{
			TPM2: &config.TPM2Config{Enabled: true, UseSimulator: true},
		},
	})

	sealer, err := s.buildTPM2PlatformSealer()
	// Release the process-global simulator singleton even if the
	// assertions below fail.
	t.Cleanup(s.closePlatformStoreTPM)

	require.NoError(t, err)
	require.NotNil(t, sealer)
	assert.True(t, sealer.CanSeal())
	assert.NotNil(t, s.platformStoreTPMClose, "the fresh probe's Close must be tracked for release at shutdown")

	_, ok := s.platformStoreTPM.(*tpm2backend.Backend)
	assert.True(t, ok, "s.platformStoreTPM must hold the concrete *tpm2backend.Backend the probe opened")

	// The Seal/Unseal round trip through platformPolicySealer is already
	// proven by platform_store_simulator_test.go's tpm2EnrolledServer-based
	// tests (which pin an exact PlatformPCR/bank at enrollment); this test's
	// job is the fresh-probe wiring above (autodetect, Close tracking, the
	// concrete backend type), not re-proving that round trip.
}

// TestBuildTPM2PlatformSealer_NotConfiguredFailsClosed proves the
// backends.tpm2 nil/disabled guard: with no pre-injected s.nodeSealTPM and
// no backends.tpm2 section, buildTPM2PlatformSealer must fail closed rather
// than attempt to autodetect hardware from a nil config.
func TestBuildTPM2PlatformSealer_NotConfiguredFailsClosed(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Backend: "file", Path: t.TempDir()},
	})

	sealer, err := s.buildTPM2PlatformSealer()
	require.Error(t, err)
	assert.Nil(t, sealer)

	var unavailableErr *ErrPlatformStoreStrategyUnavailable
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "tpm2", unavailableErr.Strategy)
}
