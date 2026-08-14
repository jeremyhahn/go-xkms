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

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// compliantConfig returns a configuration that ComplianceGaps accepts, so a
// test can isolate the effect of a single setting.
func compliantConfig() *Config {
	c := &Config{}
	c.Barrier.Enabled = true
	c.TLS.Enabled = true
	c.Auth.Enabled = true
	c.Auth.Type = "mtls"
	c.CA = &ca.MultiIdentityCAConfig{}
	return c
}

// TestComplianceGaps_IgnoresAlgorithmPolicy pins the decision that algorithm
// approval is NOT a configuration concern.
//
// Which digests and key-wrap constructions are permitted follows the process's
// FIPS mode (GOFIPS140 / GODEBUG=fips140), which pkg/types reads from
// crypto/fips140. xkms is not a FIPS-only implementation: outside FIPS mode it
// must be able to serve the SHA-1/MD5 mechanisms PKCS#11 and TLS define, so a
// compliance gate that refused to start over them would make the daemon unable
// to serve its own specification — while adding nothing, because under FIPS
// mode the validated module withholds those mechanisms at the module boundary
// regardless of what any YAML file says.
//
// The gate therefore reports only *absent security controls*
// (encryption-at-rest, TLS, authentication, a CA), never algorithm selection.
func TestComplianceGaps_IgnoresAlgorithmPolicy(t *testing.T) {
	c := compliantConfig()

	gaps := c.ComplianceGaps()
	if len(gaps) != 0 {
		t.Fatalf("compliant config reported gaps: %v", gaps)
	}

	// No gap may ever be phrased in terms of algorithm policy: those knobs no
	// longer exist, and re-introducing one as a startup refusal would break
	// PKCS#11 conformance deployments.
	for _, gap := range gaps {
		for _, forbidden := range []string{"allow_weak_hashes", "allow_legacy_key_wrap", "hash algorithms"} {
			if strings.Contains(gap, forbidden) {
				t.Errorf("algorithm policy must not be a compliance gap, got: %q", gap)
			}
		}
	}
}

// TestComplianceGaps_ReportsAbsentControls is the converse: the gate must
// still fire for every genuinely missing security control, so removing the
// algorithm knobs did not weaken it.
func TestComplianceGaps_ReportsAbsentControls(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		expect string
	}{
		{"no encryption at rest", func(c *Config) { c.Barrier.Enabled = false }, "barrier.enabled=false"},
		{"no TLS", func(c *Config) { c.TLS.Enabled = false }, "tls.enabled=false"},
		{"no authentication", func(c *Config) { c.Auth.Enabled = false }, "auth.enabled=false"},
		{"no CA", func(c *Config) { c.CA = nil }, "ca is unset"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := compliantConfig()
			tc.mutate(c)

			gaps := c.ComplianceGaps()
			if len(gaps) == 0 {
				t.Fatal("expected a compliance gap")
			}
			found := false
			for _, gap := range gaps {
				if strings.Contains(gap, tc.expect) {
					found = true
				}
			}
			if !found {
				t.Errorf("gap does not name %q: %v", tc.expect, gaps)
			}
		})
	}
}
