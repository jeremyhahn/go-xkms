//go:build tpm_simulator

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

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestNodeSealFlip_EncryptsDataPlaneAtRest_TPM2 engages the node-barrier flip
// with the tpm2 strategy on the in-process simulator. A software strategy
// never auto-unseals from configuration, so only a hardware strategy engages
// the flip unattended; this exercises the real autodetect and seal path with
// no external device. The plaintext control lives in node_seal_test.go.
func TestNodeSealFlip_EncryptsDataPlaneAtRest_TPM2(t *testing.T) {
	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "tpm2"}
	cfg.Backends.TPM2 = &config.TPM2Config{UseSimulator: true}
	dir := writeNodeSealSentinel(t, cfg, nodeSealSentinel)
	assert.False(t, dirContainsBytes(t, dir, nodeSealSentinel),
		"with the node-barrier flip the sentinel MUST be encrypted on disk")
}
