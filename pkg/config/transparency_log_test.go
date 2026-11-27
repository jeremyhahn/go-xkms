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

import "testing"

func TestTransparencyLogEnabled_UnsetTakesBuildDefault(t *testing.T) {
	cfg := &Config{}
	if got := cfg.TransparencyLogEnabled(); got != transparencyLogDefault {
		t.Errorf("TransparencyLogEnabled() = %v with no setting, want the build default %v", got, transparencyLogDefault)
	}
}

func TestTransparencyLogEnabled_ExplicitOverridesDefault(t *testing.T) {
	for _, want := range []bool{true, false} {
		enabled := want
		cfg := &Config{TransparencyLog: TransparencyLogConfig{Enabled: &enabled}}
		if got := cfg.TransparencyLogEnabled(); got != want {
			t.Errorf("TransparencyLogEnabled() = %v with enabled: %v", got, want)
		}
	}
}
