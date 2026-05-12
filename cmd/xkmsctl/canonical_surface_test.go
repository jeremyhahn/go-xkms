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
	"admin-bundle",
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

// TestCanonicalSurface_BarrierUnsealAcceptsShare verifies that the
// barrier unseal command accepts the canonical --share flag.
func TestCanonicalSurface_BarrierUnsealAcceptsShare(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"barrier", "unseal"})
	if err != nil {
		t.Fatalf("barrier unseal not registered: %v", err)
	}
	if cmd.Flags().Lookup("share") == nil {
		t.Errorf("barrier unseal --share flag missing (canonical replacement for unseal-share)")
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
