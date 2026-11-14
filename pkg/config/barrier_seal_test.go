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
	"time"

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

// TestBarrierConfig_SealedWindowTimeoutDuration verifies the default, the
// spellings that disable the window, a parsed duration, and that a malformed
// or negative value is refused rather than read as "no timeout".
func TestBarrierConfig_SealedWindowTimeoutDuration(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    time.Duration
		wantErr string
	}{
		{name: "empty selects the default", value: "", want: DefaultSealedWindowTimeout},
		{name: "blank selects the default", value: "  ", want: DefaultSealedWindowTimeout},
		{name: "zero disables", value: "0", want: 0},
		{name: "none disables", value: "none", want: 0},
		{name: "disabled is case-insensitive", value: " Disabled ", want: 0},
		{name: "duration parses", value: "90s", want: 90 * time.Second},
		{name: "malformed is refused", value: "ten minutes", wantErr: "is not a valid duration"},
		{name: "negative is refused", value: "-5m", wantErr: "must not be negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BarrierConfig{SealedWindowTimeout: tt.value}.SealedWindowTimeoutDuration()
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.ErrorContains(t, err, "barrier.sealed_window_timeout")
				assert.Zero(t, got)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestComplianceGaps_EveryBarrierStrategyEncryptsAtRest proves an enabled
// barrier closes the encryption-at-rest gap whatever its strategy: the qrdb
// node's own barrier is the only barrier, and every strategy -- including
// the cloud-KMS ones -- seals it.
func TestComplianceGaps_EveryBarrierStrategyEncryptsAtRest(t *testing.T) {
	strategies := []string{"none", "passphrase", "shamir", "tpm2", "pkcs11", "awskms", "gcpkms", "azurekv", "vault"}
	for _, strategy := range strategies {
		cfg := secureBarrierConfig()
		cfg.Barrier.Strategy = strategy
		assert.False(t, hasBarrierGap(cfg), "strategy %q", strategy)
	}
}

// TestComplianceGaps_DisabledBarrierIsAGap proves a disabled barrier is still
// reported: the data plane would be stored in plaintext.
func TestComplianceGaps_DisabledBarrierIsAGap(t *testing.T) {
	cfg := secureBarrierConfig()
	cfg.Barrier.Enabled = false
	assert.True(t, hasBarrierGap(cfg))
}

// secureBarrierConfig returns a config with TLS, auth and a CA present, so
// only the barrier can contribute a compliance gap.
func secureBarrierConfig() *Config {
	return &Config{
		Barrier: BarrierConfig{Enabled: true, Strategy: "passphrase"},
		TLS:     TLSConfig{Enabled: true},
		Auth:    AuthConfig{Enabled: true, Type: "jwt"},
		CA:      &ca.MultiIdentityCAConfig{},
	}
}

// hasBarrierGap reports whether cfg's compliance gaps include one about the
// barrier.
func hasBarrierGap(cfg *Config) bool {
	for _, g := range cfg.ComplianceGaps() {
		if strings.Contains(g, "barrier") {
			return true
		}
	}
	return false
}
