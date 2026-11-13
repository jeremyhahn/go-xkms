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

package client

import (
	"errors"
	"testing"
	"time"
)

// TestConfig_Validate pins that a config missing both fields reports the
// server URL first; each single-field refusal is asserted through NewClient.
func TestConfig_Validate(t *testing.T) {
	err := (&Config{}).Validate()
	if !errors.Is(err, ErrServerURLRequired) {
		t.Errorf("Validate() error = %v, want %v", err, ErrServerURLRequired)
	}
}

func TestConfig_SetDefaults(t *testing.T) {
	cfg := &Config{Timeout: 10 * time.Second}
	cfg.SetDefaults()
	if cfg.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, 10*time.Second)
	}
}
