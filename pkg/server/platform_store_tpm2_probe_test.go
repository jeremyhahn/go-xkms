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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// TestBuildTPM2PlatformSealer_OpenFailureCarriesProbeError proves an
// explicitly configured tpm2 strategy whose TPM cannot be opened fails with
// the typed ErrPlatformStoreStrategyUnavailable carrying the
// *seal.TPM2ProbeError cause, instead of the old "no usable TPM" verdict that
// dropped why the open failed (go-xkms#1528).
func TestBuildTPM2PlatformSealer_OpenFailureCarriesProbeError(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Datastore: config.DatastoreConfig{Engine: "file", Path: t.TempDir()},
		Backends: config.BackendsConfig{
			TPM2: &config.TPM2Config{
				Enabled:    true,
				DevicePath: filepath.Join(t.TempDir(), "no-such-tpm"),
			},
		},
	})

	sealer, err := s.buildTPM2PlatformSealer()
	t.Cleanup(s.closePlatformStoreTPM)
	require.Error(t, err)
	assert.Nil(t, sealer)
	assert.Nil(t, s.platformStoreTPMClose, "a failed open has nothing to release")

	var unavailableErr *ErrPlatformStoreStrategyUnavailable
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "tpm2", unavailableErr.Strategy)

	var probeErr *seal.TPM2ProbeError
	require.ErrorAs(t, err, &probeErr, "the TPM open's cause must survive")
	assert.NotErrorIs(t, err, seal.ErrTPM2ProbeTimeout, "a missing device fails the open, it does not time out")
}

// TestErrPlatformStoreStrategyUnavailable_Unwrap proves the cause is reported
// in the message and reachable through errors.Is, and that an error without
// a cause keeps the plain message.
func TestErrPlatformStoreStrategyUnavailable_Unwrap(t *testing.T) {
	withCause := &ErrPlatformStoreStrategyUnavailable{
		Strategy: "tpm2",
		Reason:   "the configured TPM could not be used",
		Err:      &seal.TPM2ProbeError{Err: seal.ErrTPM2ProbeTimeout},
	}
	assert.ErrorIs(t, withCause, seal.ErrTPM2ProbeTimeout)
	assert.Contains(t, withCause.Error(), seal.ErrTPM2ProbeTimeout.Error())

	withoutCause := &ErrPlatformStoreStrategyUnavailable{Strategy: "tpm2", Reason: "not configured"}
	assert.NoError(t, withoutCause.Unwrap())
	assert.Equal(t, `platform store: strategy "tpm2" is not available: not configured`, withoutCause.Error())
}
