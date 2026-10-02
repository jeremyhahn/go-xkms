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

package config

import "testing"

// go-xkms#1392: endorse-01 proves nothing about the key it certifies, so the
// External Account Binding is its only control and unset means required.
func TestACMEConfig_EndorseEABIsRequired(t *testing.T) {
	yes, no := true, false
	tests := []struct {
		name string
		cfg  *ACMEConfig
		want bool
	}{
		{"unset is required", &ACMEConfig{}, true},
		{"no ACME section is required", nil, true},
		{"explicitly true", &ACMEConfig{EndorseEABRequired: &yes}, true},
		{"explicitly false waives it", &ACMEConfig{EndorseEABRequired: &no}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.EndorseEABIsRequired(); got != tt.want {
				t.Fatalf("EndorseEABIsRequired() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The YAML key an operator writes to waive EAB, and the environment variable,
// reach the field; a file that never mentions it leaves it required.
func TestLoad_ACMEEndorseEABRequired(t *testing.T) {
	load := func(t *testing.T, acmeLines string) *ACMEConfig {
		t.Helper()
		cfg, err := Load(writeConfigBody(t, "", "\nacme:\n  challenges:\n    http01: true\n"+acmeLines))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		return cfg.ACME
	}

	t.Run("an acme section that omits the key requires EAB", func(t *testing.T) {
		if !load(t, "").EndorseEABIsRequired() {
			t.Fatal("EAB is not required when the key is absent")
		}
	})
	t.Run("endorse_eab_required: false waives it", func(t *testing.T) {
		if load(t, "  endorse_eab_required: false\n").EndorseEABIsRequired() {
			t.Fatal("endorse_eab_required: false did not waive EAB")
		}
	})
	t.Run("endorse_eab_required: true requires it", func(t *testing.T) {
		if !load(t, "  endorse_eab_required: true\n").EndorseEABIsRequired() {
			t.Fatal("endorse_eab_required: true did not require EAB")
		}
	})
	t.Run("the environment waives it", func(t *testing.T) {
		t.Setenv("XKMS_ACME_ENDORSE_EAB_REQUIRED", "false")
		if load(t, "").EndorseEABIsRequired() {
			t.Fatal("XKMS_ACME_ENDORSE_EAB_REQUIRED=false did not waive EAB")
		}
	})
}
