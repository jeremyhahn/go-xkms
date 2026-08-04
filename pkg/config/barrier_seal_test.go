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

func TestComplianceGaps_QRDBBarrierAutoUnseal(t *testing.T) {
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

	hasAutoUnsealGap := func(cfg *Config) bool {
		for _, g := range cfg.ComplianceGaps() {
			if strings.Contains(g, "cannot auto-unseal") {
				return true
			}
		}
		return false
	}

	// qrdb + passphrase strategy + no passphrase → gap (would be plaintext).
	assert.True(t, hasAutoUnsealGap(base()), "qrdb barrier with no auto-unseal creds is a gap")

	// A boot passphrase closes it.
	withPass := base()
	withPass.Barrier.Passphrase = "boot-secret"
	assert.False(t, hasAutoUnsealGap(withPass), "a boot passphrase auto-unseals")

	// A hardware strategy closes it (TPM auto-unseals at boot).
	withTPM := base()
	withTPM.Barrier.Strategy = "tpm2"
	assert.False(t, hasAutoUnsealGap(withTPM), "a hardware strategy auto-unseals")

	// File storage never hits this gap (no embedded node / different barrier).
	fileCfg := base()
	fileCfg.Storage.Backend = "file"
	assert.False(t, hasAutoUnsealGap(fileCfg), "file storage uses xkms's own barrier")
}

func TestApplyEnvOverrides_Seal(t *testing.T) {
	t.Setenv("XKMS_SEAL_STRATEGY", "tpm2")
	t.Setenv("XKMS_SEAL_PASSPHRASE", "s3cr3t-boot-secret")

	cfg := &Config{}
	applyEnvOverrides(cfg)

	assert.Equal(t, "tpm2", cfg.Barrier.Strategy)
	assert.Equal(t, "s3cr3t-boot-secret", cfg.Barrier.Passphrase)
}
