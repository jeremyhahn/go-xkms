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
	"init",
	"auth",
	"barrier",
	"ceremony",
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

// canonicalInitFlagNames lists the canonical init flag names.
var canonicalInitFlagNames = []string{
	"so-pin",
	"user-pin",
	"barrier-strategy",
	"shares",
	"threshold",
	"hostname",
	"sans",
}

// canonicalBarrierVerbs lists the canonical 9-verb barrier surface.
// "recovery" is a verb group whose subcommands are checked separately.
var canonicalBarrierVerbs = []string{
	"status",
	"init",
	"init-shamir",
	"unseal",
	"unseal-shares",
	"seal",
	"rekey",
	"recovery",
}

// TestCanonicalSurface_RootHasInit verifies the root "init" command
// is registered.
func TestCanonicalSurface_RootHasInit(t *testing.T) {
	if _, _, err := rootCmd.Find([]string{"init"}); err != nil {
		t.Fatalf("expected canonical 'init' command at xkmsctl root: %v", err)
	}
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

// TestCanonicalSurface_InitFlagsExposed verifies the canonical init
// flag set is fully exposed on initCmd.
func TestCanonicalSurface_InitFlagsExposed(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"init"})
	if err != nil {
		t.Fatalf("init not found: %v", err)
	}
	for _, name := range canonicalInitFlagNames {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("canonical init flag --%s missing", name)
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

// TestCanonicalSurface_BarrierHasAllVerbs verifies the canonical
// 9-verb barrier surface is present.
func TestCanonicalSurface_BarrierHasAllVerbs(t *testing.T) {
	for _, verb := range canonicalBarrierVerbs {
		if _, _, err := rootCmd.Find([]string{"barrier", verb}); err != nil {
			t.Errorf("canonical barrier verb %q missing: %v", verb, err)
		}
	}
}

// TestCanonicalSurface_BarrierRecoveryHasSubcommands verifies the
// recovery group has its canonical subcommands.
func TestCanonicalSurface_BarrierRecoveryHasSubcommands(t *testing.T) {
	for _, verb := range []string{"generate", "recover"} {
		if _, _, err := rootCmd.Find([]string{"barrier", "recovery", verb}); err != nil {
			t.Errorf("canonical barrier recovery verb %q missing: %v", verb, err)
		}
	}
}

// TestCanonicalSurface_BarrierUnsealAcceptsPassphrase verifies the canonical
// `barrier unseal --passphrase` flag.
func TestCanonicalSurface_BarrierUnsealAcceptsPassphrase(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"barrier", "unseal"})
	if err != nil {
		t.Fatalf("barrier unseal not registered: %v", err)
	}
	if cmd.Flags().Lookup("passphrase") == nil {
		t.Errorf("barrier unseal --passphrase flag missing (canonical)")
	}
}

// TestCanonicalSurface_BarrierUnsealSharesAcceptsShare verifies the
// canonical `barrier unseal-shares --share` and `--shares-file` flags.
func TestCanonicalSurface_BarrierUnsealSharesAcceptsShare(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"barrier", "unseal-shares"})
	if err != nil {
		t.Fatalf("barrier unseal-shares not registered: %v", err)
	}
	for _, flag := range []string{"share", "shares-file"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("barrier unseal-shares --%s flag missing (canonical)", flag)
		}
	}
}

// TestCanonicalSurface_BarrierInitAcceptsStrategyAndPINs verifies the
// canonical `barrier init` flag set.
func TestCanonicalSurface_BarrierInitAcceptsStrategyAndPINs(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"barrier", "init"})
	if err != nil {
		t.Fatalf("barrier init not registered: %v", err)
	}
	for _, flag := range []string{"barrier-strategy", "passphrase", "so-pin", "user-pin"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("barrier init --%s flag missing (canonical)", flag)
		}
	}
}

// TestCanonicalSurface_BarrierInitShamirFlags verifies the canonical
// `barrier init-shamir` flag set.
func TestCanonicalSurface_BarrierInitShamirFlags(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"barrier", "init-shamir"})
	if err != nil {
		t.Fatalf("barrier init-shamir not registered: %v", err)
	}
	for _, flag := range []string{"passphrase", "threshold", "total", "so-pin", "user-pin"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("barrier init-shamir --%s flag missing (canonical)", flag)
		}
	}
}

// TestCanonicalSurface_BarrierRekeyFlags verifies the canonical
// `barrier rekey` flag set.
func TestCanonicalSurface_BarrierRekeyFlags(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"barrier", "rekey"})
	if err != nil {
		t.Fatalf("barrier rekey not registered: %v", err)
	}
	for _, flag := range []string{"so-pin", "threshold", "total"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("barrier rekey --%s flag missing (canonical)", flag)
		}
	}
	if cmd.Flags().Lookup("passphrase") != nil {
		t.Error("barrier rekey --passphrase must not exist (canonical: no secret on the wire)")
	}
}

// TestCanonicalSurface_BarrierSealFlags verifies the canonical
// `barrier seal` flag set.
func TestCanonicalSurface_BarrierSealFlags(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"barrier", "seal"})
	if err != nil {
		t.Fatalf("barrier seal not registered: %v", err)
	}
	for _, flag := range []string{"so-pin", "assume-yes"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("barrier seal --%s flag missing (canonical)", flag)
		}
	}
}

// TestCanonicalSurface_BarrierRecoveryGenerateFlags verifies the canonical
// `barrier recovery generate` flag set.
func TestCanonicalSurface_BarrierRecoveryGenerateFlags(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"barrier", "recovery", "generate"})
	if err != nil {
		t.Fatalf("barrier recovery generate not registered: %v", err)
	}
	for _, flag := range []string{"threshold", "total", "so-pin"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("barrier recovery generate --%s flag missing (canonical)", flag)
		}
	}
}

// TestCanonicalSurface_BarrierRecoveryRecoverFlags verifies the canonical
// `barrier recovery recover` flag set.
func TestCanonicalSurface_BarrierRecoveryRecoverFlags(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"barrier", "recovery", "recover"})
	if err != nil {
		t.Fatalf("barrier recovery recover not registered: %v", err)
	}
	if cmd.Flags().Lookup("share") == nil {
		t.Errorf("barrier recovery recover --share flag missing (canonical)")
	}
}

// TestCanonicalSurface_BarrierRetiredVerbs verifies the legacy verbs
// that are NOT part of the canonical 9 are no longer attached.
func TestCanonicalSurface_BarrierRetiredVerbs(t *testing.T) {
	retired := [][]string{
		{"barrier", "root-token"},
		{"barrier", "shares"},
		{"barrier", "recovery", "delete"},
	}
	for _, path := range retired {
		// rootCmd.Find returns the closest matching parent for unknown
		// subcommands; we check for the actual verb by walking commands
		// under the parent and matching the leaf name.
		parent, _, err := rootCmd.Find(path[:len(path)-1])
		if err != nil {
			// Parent does not exist (e.g., barrier shares); that itself
			// satisfies the retirement requirement.
			continue
		}
		leaf := path[len(path)-1]
		for _, c := range parent.Commands() {
			if c.Name() == leaf {
				t.Errorf("retired verb %v still attached to xkmsctl barrier surface", path)
			}
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

// TestCanonicalSurface_CeremonyHasSubcommands verifies the canonical
// ceremony group has status / claim-cert / claim-share / sign-csr.
func TestCanonicalSurface_CeremonyHasSubcommands(t *testing.T) {
	for _, verb := range []string{"status", "claim-cert", "claim-share", "sign-csr"} {
		if _, _, err := rootCmd.Find([]string{"ceremony", verb}); err != nil {
			t.Errorf("ceremony %s missing: %v", verb, err)
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
