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

	"gopkg.in/yaml.v3"
)

// TestComplianceGaps_CORSWildcard covers the CORS posture: disabled by
// default (no gap), explicit origins allowed (no gap), and the wildcard
// origin reported as a gap, which the daemon treats as fatal at startup.
func TestComplianceGaps_CORSWildcard(t *testing.T) {
	t.Run("default posture reports no gap", func(t *testing.T) {
		c := compliantConfig()
		if c.CORS.Enabled {
			t.Fatal("cors.enabled must default to false")
		}
		if gaps := c.ComplianceGaps(); len(gaps) != 0 {
			t.Errorf("compliant config reported gaps: %v", gaps)
		}
	})

	t.Run("explicit origins report no gap", func(t *testing.T) {
		c := compliantConfig()
		c.CORS.Enabled = true
		c.CORS.AllowedOrigins = []string{"https://ui.example", "https://ops.example"}

		if gaps := c.ComplianceGaps(); len(gaps) != 0 {
			t.Errorf("explicit-origin config reported gaps: %v", gaps)
		}
	})

	t.Run("wildcard origin is a gap", func(t *testing.T) {
		c := compliantConfig()
		c.CORS.Enabled = true
		c.CORS.AllowedOrigins = []string{"https://ui.example", "*"}

		gaps := c.ComplianceGaps()
		if len(gaps) != 1 {
			t.Fatalf("want exactly 1 gap, got %d: %v", len(gaps), gaps)
		}
		if !strings.Contains(gaps[0], "cors.allowed_origins") {
			t.Errorf("gap does not name the setting an operator has to change: %q", gaps[0])
		}
	})

	t.Run("wildcard while disabled reports no gap", func(t *testing.T) {
		c := compliantConfig()
		c.CORS.Enabled = false
		c.CORS.AllowedOrigins = []string{"*"}

		if gaps := c.ComplianceGaps(); len(gaps) != 0 {
			t.Errorf("disabled CORS reported gaps: %v", gaps)
		}
	})
}

// TestCORSConfig_YAML proves the yaml wire names stay stable.
func TestCORSConfig_YAML(t *testing.T) {
	src := `
cors:
  enabled: true
  allowed_origins:
    - https://ui.example
  allow_credentials: true
  max_age_seconds: 600
`
	var c Config
	if err := yaml.Unmarshal([]byte(src), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !c.CORS.Enabled {
		t.Error("cors.enabled not decoded")
	}
	if len(c.CORS.AllowedOrigins) != 1 || c.CORS.AllowedOrigins[0] != "https://ui.example" {
		t.Errorf("cors.allowed_origins not decoded: %v", c.CORS.AllowedOrigins)
	}
	if !c.CORS.AllowCredentials {
		t.Error("cors.allow_credentials not decoded")
	}
	if c.CORS.MaxAgeSeconds != 600 {
		t.Errorf("cors.max_age_seconds not decoded: %d", c.CORS.MaxAgeSeconds)
	}
}
