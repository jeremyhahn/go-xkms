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

package main

import (
	"testing"
)

// canonicalRootSubcommands lists the locked canonical command names
// that MUST appear at the xkmsctl root per
// docs/08-bootstrap-auth-architecture.md §6.
var canonicalRootSubcommands = []string{
	"auth",
	"ca",
	"bootstrap",
	"credential",
	"cluster",
	"rebalance",
}

// canonicalClusterVerbs lists the locked "cluster" verb surface driving
// go-qrdb's control plane hosted by xkmsd.
var canonicalClusterVerbs = []string{
	"status",
	"members",
	"add",
	"remove",
}

// canonicalRebalanceVerbs lists the locked "rebalance" verb surface
// mapping 1:1 onto qrdb's transport.RebalanceClient.
var canonicalRebalanceVerbs = []string{
	"stats",
	"plan",
	"execute",
	"report",
}

// TestCanonicalSurface_RootHasAllSubcommands verifies every canonical
// subcommand is at the root.
func TestCanonicalSurface_RootHasAllSubcommands(t *testing.T) {
	for _, name := range canonicalRootSubcommands {
		if _, _, err := rootCmd.Find([]string{name}); err != nil {
			t.Errorf("canonical command %q missing from xkmsctl root: %v", name, err)
		}
	}
}

// TestCanonicalSurface_ClusterHasAllVerbs verifies the canonical cluster
// verb surface is present.
func TestCanonicalSurface_ClusterHasAllVerbs(t *testing.T) {
	for _, verb := range canonicalClusterVerbs {
		if _, _, err := rootCmd.Find([]string{"cluster", verb}); err != nil {
			t.Errorf("canonical cluster verb %q missing: %v", verb, err)
		}
	}
}

// TestCanonicalSurface_ClusterVerbFlags verifies the canonical cluster
// flag surface: --shard everywhere plus the add/remove replica flags.
func TestCanonicalSurface_ClusterVerbFlags(t *testing.T) {
	for _, verb := range canonicalClusterVerbs {
		cmd, _, err := rootCmd.Find([]string{"cluster", verb})
		if err != nil {
			t.Fatalf("cluster %s not registered: %v", verb, err)
		}
		if cmd.Flags().Lookup("shard") == nil {
			t.Errorf("cluster %s --shard flag missing (canonical)", verb)
		}
	}
	addCmd, _, err := rootCmd.Find([]string{"cluster", "add"})
	if err != nil {
		t.Fatalf("cluster add not registered: %v", err)
	}
	for _, flag := range []string{"replica-id", "raft-address"} {
		if addCmd.Flags().Lookup(flag) == nil {
			t.Errorf("cluster add --%s flag missing (canonical)", flag)
		}
	}
	removeCmd, _, err := rootCmd.Find([]string{"cluster", "remove"})
	if err != nil {
		t.Fatalf("cluster remove not registered: %v", err)
	}
	if removeCmd.Flags().Lookup("replica-id") == nil {
		t.Errorf("cluster remove --replica-id flag missing (canonical)")
	}
}

// TestCanonicalSurface_RebalanceHasAllVerbs verifies the canonical
// rebalance verb surface is present.
func TestCanonicalSurface_RebalanceHasAllVerbs(t *testing.T) {
	for _, verb := range canonicalRebalanceVerbs {
		if _, _, err := rootCmd.Find([]string{"rebalance", verb}); err != nil {
			t.Errorf("canonical rebalance verb %q missing: %v", verb, err)
		}
	}
}

// TestCanonicalSurface_RebalanceVerbFlags verifies the canonical
// rebalance flag surface per verb.
func TestCanonicalSurface_RebalanceVerbFlags(t *testing.T) {
	statsCmd, _, err := rootCmd.Find([]string{"rebalance", "stats"})
	if err != nil {
		t.Fatalf("rebalance stats not registered: %v", err)
	}
	if statsCmd.Flags().Lookup("shard") == nil {
		t.Errorf("rebalance stats --shard flag missing (canonical)")
	}

	planCmd, _, err := rootCmd.Find([]string{"rebalance", "plan"})
	if err != nil {
		t.Fatalf("rebalance plan not registered: %v", err)
	}
	for _, flag := range []string{"max-moves", "dry-run", "target-balance", "out"} {
		if planCmd.Flags().Lookup(flag) == nil {
			t.Errorf("rebalance plan --%s flag missing (canonical)", flag)
		}
	}

	execCmd, _, err := rootCmd.Find([]string{"rebalance", "execute"})
	if err != nil {
		t.Fatalf("rebalance execute not registered: %v", err)
	}
	for _, flag := range []string{"plan", "max-moves", "target-balance"} {
		if execCmd.Flags().Lookup(flag) == nil {
			t.Errorf("rebalance execute --%s flag missing (canonical)", flag)
		}
	}
}

// TestCanonicalSurface_BootstrapHasDirect verifies the bootstrap group
// includes the new "direct" mode.
func TestCanonicalSurface_BootstrapHasDirect(t *testing.T) {
	for _, mode := range []string{"auto", "dane", "noise", "spki", "direct"} {
		if _, _, err := rootCmd.Find([]string{"bootstrap", mode}); err != nil {
			t.Errorf("bootstrap %s missing: %v", mode, err)
		}
	}
}

// TestCanonicalSurface_AuthHasFactor verifies the auth group has the
// N-factor management surface.
func TestCanonicalSurface_AuthHasFactor(t *testing.T) {
	for _, verb := range []string{"login", "factor"} {
		if _, _, err := rootCmd.Find([]string{"auth", verb}); err != nil {
			t.Errorf("auth %s missing: %v", verb, err)
		}
	}
	for _, verb := range []string{"list", "add", "remove", "rotate", "relabel"} {
		if _, _, err := rootCmd.Find([]string{"auth", "factor", verb}); err != nil {
			t.Errorf("auth factor %s missing: %v", verb, err)
		}
	}
}

// TestCanonicalSurface_CredentialHasSubcommands verifies the canonical
// credential group has submit / list / rotate.
func TestCanonicalSurface_CredentialHasSubcommands(t *testing.T) {
	for _, verb := range []string{"submit", "list", "rotate"} {
		if _, _, err := rootCmd.Find([]string{"credential", verb}); err != nil {
			t.Errorf("credential %s missing: %v", verb, err)
		}
	}
}

// TestCanonicalSurface_TransportDefaultsToUnix verifies the canonical
// default transport.
func TestCanonicalSurface_TransportDefaultsToUnix(t *testing.T) {
	if DefaultTransport != "unix" {
		t.Errorf("DefaultTransport = %q, want %q", DefaultTransport, "unix")
	}
	transportFlag := rootCmd.PersistentFlags().Lookup("transport")
	if transportFlag == nil {
		t.Fatal("root command missing --transport persistent flag")
	}
	if transportFlag.DefValue != DefaultTransport {
		t.Errorf("--transport DefValue = %q, want %q", transportFlag.DefValue, DefaultTransport)
	}
}

// TestCanonicalSurface_RemovedCommandsAreAbsent proves the surfaces that moved
// to go-qrdb's own CLI -- the init ceremony, the barrier verbs, custodian
// groups, shares, backup and audit -- are not served by xkmsctl.
func TestCanonicalSurface_RemovedCommandsAreAbsent(t *testing.T) {
	for _, name := range []string{"init", "barrier", "ceremony", "custodian", "share", "backup", "audit"} {
		cmd, args, err := rootCmd.Find([]string{name})
		if err == nil && cmd != rootCmd {
			t.Errorf("command %q must not be registered at the xkmsctl root", name)
		}
		if err == nil && cmd == rootCmd && len(args) == 0 {
			t.Errorf("Find(%q) resolved to no argument", name)
		}
	}
}
