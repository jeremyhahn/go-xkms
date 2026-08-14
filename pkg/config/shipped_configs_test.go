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
	"os"
	"path/filepath"
	"testing"
)

// shippedDaemonConfigs are the configs in configs/ that are handed to xkmsd.
//
// xkms-client.yaml is deliberately absent: it configures a client, enables no
// server protocol, and is never passed to the daemon, so Validate rejects it by
// design.
var shippedDaemonConfigs = []string{
	"xkmsd.yaml",
	"xkmsd-dev.yaml",
	"xkmsd-local.yaml",
	"xkmsd-integration.yaml",
}

// TestShippedDaemonConfigsAreCompliant pins the property that every config we
// ship can actually start a daemon.
//
// cmd/xkmsd refuses to serve a configuration with any compliance gap and has no
// override flag, so a shipped config that reports a gap is not merely insecure
// — it is inert, and the failure surfaces as a container that will not come up
// rather than as anything pointing at the config. That is exactly how
// configs/xkmsd-integration.yaml silently disabled the pkcs11-backend and gRPC
// integration lanes: the compose service exited at startup and the suite fell
// through to a software-only fallback daemon, which looked like a backend
// defect. This test is the guard for that, and it fails with the offending file
// and the exact gaps rather than leaving it to be rediscovered downstream.
func TestShippedDaemonConfigsAreCompliant(t *testing.T) {
	for _, name := range shippedDaemonConfigs {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "configs", name)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("shipped config is missing: %v", err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load(%s) failed, so xkmsd could not start with it: %v", name, err)
			}
			gaps := cfg.ComplianceGaps()
			for _, gap := range gaps {
				t.Errorf("compliance gap: %s", gap)
			}
			if len(gaps) > 0 {
				t.Fatalf("%s reports %d compliance gap(s); cmd/xkmsd refuses to start with it "+
					"and offers no override", name, len(gaps))
			}
		})
	}
}

// TestConformanceConfigsAllowWeakHashes pins the weak-hash opt-in on the two
// configs whose suites depend on it.
//
// The PKCS#11 module advertises the OASIS SHA-1 mechanisms (CKM_SHA1_RSA_PKCS,
// CKM_ECDSA_SHA1), and the daemon performs the digest the module names on the
// wire. Since xkms refuses the collision-broken digests by default, a
// conformance run against a daemon that has not opted in fails on every one of
// those mechanisms — and it fails as a mechanism error, which reads like a
// module defect rather than a configuration choice.
//
// Asserting it here keeps the two files in step: scripts/start-test-xkmsd.sh
// generates the fallback daemon's config with this set, and
// configs/xkmsd-integration.yaml serves the same socket from compose. They
// drifted once already, with only the script carrying the opt-in.
func TestConformanceConfigsAllowWeakHashes(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "xkmsd-integration.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Crypto.AllowWeakHashes {
		t.Error("crypto.allow_weak_hashes is not set, so the SHA-1 mechanisms the " +
			"PKCS#11 conformance suite exercises will be refused by the daemon")
	}
}
