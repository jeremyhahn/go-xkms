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

package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

func TestBarrierConfig_SealStrategy(t *testing.T) {
	assert.Equal(t, "passphrase", BarrierConfig{}.SealStrategy(), "empty defaults to passphrase")
	assert.Equal(t, "tpm2", BarrierConfig{Strategy: "tpm2"}.SealStrategy())
	assert.Equal(t, "none", BarrierConfig{Strategy: "none"}.SealStrategy())
}

func TestBarrierConfig_IsHardwareSealStrategy(t *testing.T) {
	hardware := []string{"tpm2", "pkcs11", "awskms", "gcpkms", "azurekv", "vault"}
	for _, s := range hardware {
		assert.True(t, BarrierConfig{Strategy: s}.IsHardwareSealStrategy(), s)
	}
	software := []string{"", "passphrase", "shamir", "none"}
	for _, s := range software {
		assert.False(t, BarrierConfig{Strategy: s}.IsHardwareSealStrategy(), s)
	}
}

// TestBarrierConfig_NodeFlipWired proves the exact strategy split the
// node-barrier flip (pkg/server's resolveNodeSeal) and ComplianceGaps both
// key off: "none"/"passphrase"/"shamir"/"tpm2" are wired to the qrdb node's
// own barrier; "pkcs11" and every cloud-KMS strategy are not (they need
// credentials only resolvable after the credential service exists, which
// itself needs the barrier they would be sealing — go-xkms#653 item 3,
// not yet approved).
func TestBarrierConfig_NodeFlipWired(t *testing.T) {
	wired := []string{"", "none", "passphrase", "shamir", "tpm2"}
	for _, s := range wired {
		assert.True(t, BarrierConfig{Strategy: s}.NodeFlipWired(), s)
	}
	notWired := []string{"pkcs11", "awskms", "gcpkms", "azurekv", "vault"}
	for _, s := range notWired {
		assert.False(t, BarrierConfig{Strategy: s}.NodeFlipWired(), s)
	}
}

// TestComplianceGaps_QRDBBarrierNodeFlipWired proves the gap tracks
// BarrierConfig.NodeFlipWired, not whether the strategy can auto-unseal
// unattended: "passphrase" and "shamir" are wired to the qrdb node's own
// barrier exactly like "none" and "tpm2" are (go-xkms#653 approved item 2)
// — the node's data plane is genuinely encrypted for all four, "passphrase"
// and "shamir" just gate access behind the sealed-window unseal ceremony
// rather than auto-unsealing. Only a strategy not yet wired to the flip
// (pkcs11, the cloud-KMS strategies) leaves the node's own data plane
// unencrypted, which is the actual gap.
func TestComplianceGaps_QRDBBarrierNodeFlipWired(t *testing.T) {
	// Base secure config (TLS/auth/CA present) so only the barrier gap varies.
	base := func() *Config {
		return &Config{
			Storage: StorageConfig{Backend: "qrdb"},
			Barrier: BarrierConfig{Enabled: true, Strategy: "passphrase"},
			TLS:     TLSConfig{Enabled: true},
			Auth:    AuthConfig{Enabled: true, Type: "jwt"},
			CA:      &ca.MultiIdentityCAConfig{},
		}
	}

	hasNodeFlipGap := func(cfg *Config) bool {
		for _, g := range cfg.ComplianceGaps() {
			if strings.Contains(g, "not wired to the qrdb node's own barrier") {
				return true
			}
		}
		return false
	}

	// Every NodeFlipWired strategy closes the gap: the node's own barrier
	// genuinely encrypts the data plane for each, auto-unsealing unattended
	// ("none", "tpm2") or via the operator-driven sealed-window ceremony
	// ("passphrase", "shamir").
	for _, strategy := range []string{"none", "passphrase", "shamir", "tpm2"} {
		cfg := base()
		cfg.Barrier.Strategy = strategy
		assert.False(t, hasNodeFlipGap(cfg), "strategy %q is wired to the node flip", strategy)
	}

	// A strategy not yet wired to the node flip leaves it open: the node's
	// own data plane stays genuinely unencrypted.
	for _, strategy := range []string{"pkcs11", "awskms", "gcpkms", "azurekv", "vault"} {
		cfg := base()
		cfg.Barrier.Strategy = strategy
		assert.True(t, hasNodeFlipGap(cfg), "strategy %q is not yet wired to the node flip", strategy)
	}

	// File storage never hits this gap (no embedded node / different barrier).
	fileCfg := base()
	fileCfg.Storage.Backend = "file"
	assert.False(t, hasNodeFlipGap(fileCfg), "file storage uses xkms's own barrier")
}
