//go:build !tpm_simulator

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

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestInitializePlatformStore_TPM2WithoutEnrolledPSRKFailsClosed proves the
// owner ruling directly: go-xkms seals under the Platform SRK only, never
// the Shared SRK, so a TPM backend this process cannot open at all must fail
// closed rather than fall back to the SSRK.
//
// This file carries the !tpm_simulator build tag deliberately -- it is not
// exercising a "TPM open but no Platform SRK enrolled" state (that state is
// covered under the tpm_simulator tag by
// platform_store_simulator_test.go's TestInitializePlatformStore_TPM2ReusesNodeSealFlip,
// which asserts the reuse invariants; see that test's doc comment). It
// exercises the case where UseSimulator: true cannot reach a TPM at all
// because the simulator isn't compiled in, so seal.BuildBestStrategy's TPM
// open fails with pkgtpm2.ErrSimulatorNotAvailable -- a different underlying
// cause than "no usable, provisioned TPM was found", but the same typed
// ErrPlatformStoreStrategyUnavailable{Strategy: "tpm2"} this test asserts.
//
// It cannot be merged into a tpm_simulator-tagged file: under that tag,
// s.buildTPM2PlatformSealer's standalone/autodetect path
// (seal.BuildBestStrategy -> pkg/backend/tpm2's NewBackend) always reaches
// NewBackend's first-boot recipe on a fresh in-memory simulator, and that
// recipe (pkg/tpm2.ProvisionFresh, added by go-xkms#681 "seal only under the
// Platform SRK") provisions the EK, SSRK AND Platform SRK together as a
// deliberate simulator-only test convenience (see that function's doc
// comment -- a physical TPM is never auto-provisioned this way). A bare
// UseSimulator: true config therefore always yields a seal-capable,
// Platform-SRK-enrolled backend under tpm_simulator, so this exact
// assertion (require.Error) cannot hold there; go-xkms#718's original
// version of this test carried that assumption and hung the whole package
// when run with tpm_simulator, because New(cfg) unexpectedly succeeded and
// the leaked simulator open (go-tpm-tools' Get() is a single global
// process-wide lock) blocked every later simulator-backed test.
func TestInitializePlatformStore_TPM2WithoutEnrolledPSRKFailsClosed(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Datastore:   config.DatastoreConfig{Engine: "file", Path: t.TempDir()},
		Credentials: config.CredentialsConfig{SealStrategy: "tpm2"},
		Backends: config.BackendsConfig{
			TPM2: &config.TPM2Config{
				Enabled:      true,
				UseSimulator: true,
			},
		},
	})

	err := s.initializePlatformStore()
	require.Error(t, err, "no Shared-SRK fallback: an unenrolled Platform SRK must fail closed")
	assert.Nil(t, s.platformStore)
	t.Cleanup(s.closePlatformStoreTPM)

	var unavailableErr *ErrPlatformStoreStrategyUnavailable
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "tpm2", unavailableErr.Strategy)
}
