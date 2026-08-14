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

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// TestUIEnabled_DefaultsToTrue proves a config without a ui section serves
// the UI: old configuration files must not silently disable it.
func TestUIEnabled_DefaultsToTrue(t *testing.T) {
	cfg := &Config{}
	if !cfg.UIEnabled() {
		t.Error("UIEnabled() = false for an unset ui section, want true")
	}
}

func TestUIEnabled_ExplicitTrue(t *testing.T) {
	enabled := true
	cfg := &Config{UI: UIConfig{Enabled: &enabled}}
	if !cfg.UIEnabled() {
		t.Error("UIEnabled() = false with enabled: true, want true")
	}
}

func TestUIEnabled_ExplicitFalse(t *testing.T) {
	enabled := false
	cfg := &Config{UI: UIConfig{Enabled: &enabled}}
	if cfg.UIEnabled() {
		t.Error("UIEnabled() = true with enabled: false, want false")
	}
}

// TestUIConfig_YAMLRoundTrip parses a full ui section and verifies every
// field lands where the REST transport expects it.
func TestUIConfig_YAMLRoundTrip(t *testing.T) {
	const doc = `
ui:
  enabled: false
  path_prefix: /console/
  redirect_root: true
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(doc), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}

	if cfg.UI.Enabled == nil || *cfg.UI.Enabled {
		t.Error("ui.enabled: false did not parse into an explicit false")
	}
	if cfg.UIEnabled() {
		t.Error("UIEnabled() = true, want false from the parsed document")
	}
	if cfg.UI.PathPrefix != "/console/" {
		t.Errorf("PathPrefix = %q, want /console/", cfg.UI.PathPrefix)
	}
	if !cfg.UI.RedirectRoot {
		t.Error("RedirectRoot = false, want true from the parsed document")
	}
}

// TestUIConfig_YAMLWithoutSection proves that a document with no ui section
// leaves the flag nil (enabled) with default prefix behavior.
func TestUIConfig_YAMLWithoutSection(t *testing.T) {
	const doc = `
server:
  rest_port: 8443
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(doc), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}

	if cfg.UI.Enabled != nil {
		t.Errorf("UI.Enabled = %v, want nil when the section is absent", *cfg.UI.Enabled)
	}
	if !cfg.UIEnabled() {
		t.Error("UIEnabled() = false without a ui section, want true")
	}
	if cfg.UI.PathPrefix != "" {
		t.Errorf("PathPrefix = %q, want empty (the transport applies the default)", cfg.UI.PathPrefix)
	}
	if cfg.UI.RedirectRoot {
		t.Error("RedirectRoot = true without a ui section, want false")
	}
}
