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

package commands

import (
	"slices"
	"strings"
	"testing"
)

// secretsFamilyVerbs lists every password, pin and piv verb that row #2321
// slice (d) puts in the CLI family x transport matrix.
var secretsFamilyVerbs = map[CommandCategory][]string{
	CategoryPassword: {
		"password unlock", "password status", "password add", "password get",
		"password list", "password update", "password access-mode",
		"password generate", "password lock", "password delete",
		"password vault status", "password vault enroll", "password vault rotate",
		"password vault recover", "password vault remove",
	},
	CategoryPIN: {
		"pin so-set", "pin so-verify", "pin so-change", "pin user-set",
		"pin user-verify", "pin user-change", "pin lockout", "pin lockout-reset",
	},
	CategoryPIV: {
		"piv list", "piv generate", "piv get", "piv csr", "piv export",
		"piv store", "piv import", "piv delete",
	},
}

func TestSecretsFamiliesCoverEveryVerb(t *testing.T) {
	for category, verbs := range secretsFamilyVerbs {
		got := map[string]CommandDefinition{}
		for _, cmd := range CommandsByCategory(category) {
			got[strings.Join(cmd.Command, " ")] = cmd
		}
		for _, verb := range verbs {
			cmd, ok := got[verb]
			if !ok {
				t.Errorf("%s: verb %q has no matrix command", category, verb)
				continue
			}
			if !cmd.RequiresServer {
				t.Errorf("%s: %q must run through the server (cfg.CreateClient)", category, verb)
			}
		}
	}
}

func TestSecretsFamiliesInAllCommands(t *testing.T) {
	seen := map[CommandCategory]int{}
	for _, cmd := range AllCommands() {
		seen[cmd.Category]++
	}
	for category, verbs := range secretsFamilyVerbs {
		if seen[category] != len(verbs) {
			t.Errorf("AllCommands: %s has %d commands, want %d", category, seen[category], len(verbs))
		}
	}
}

// TestSecretsMatrixCells checks that every password, pin and piv family has a
// cell on each of the six transports, and that a cell with no standalone run
// names why.
func TestSecretsMatrixCells(t *testing.T) {
	for category := range secretsFamilyVerbs {
		if !slices.Contains(CommandFamilies(), category) {
			t.Errorf("CommandFamilies() misses %s", category)
		}
		for _, protocol := range CLIProtocols() {
			cell := MatrixCellFor(category, protocol, []string{"frost"})
			if cell.Runs == 0 && cell.Reason == "" {
				t.Errorf("(%s, %s): no run and no reason", category, protocol)
			}
			for _, cmd := range CommandsByCategory(category) {
				if reason, skip := SkipReason(cmd, protocol, nil); skip && reason == "" {
					t.Errorf("(%s, %s) %s: skipped without a reason", category, protocol, cmd.Name)
				}
			}
		}
	}
}

func TestSecretsSetupOrder(t *testing.T) {
	order := SecretsSetupOrder()
	index := map[string]int{}
	for i, name := range order {
		index[name] = i
	}
	before := [][2]string{
		{"pin-so-set", "pin-user-set"},
		{"pin-so-set", "pin-so-verify"},
		{"pin-user-set", "pin-user-verify"},
		{"password-unlock", "password-add"},
		{"password-add", "password-get"},
		{"password-add", "password-delete"},
		{"piv-generate", "piv-csr"},
		{"piv-generate", "piv-export"},
		{"piv-generate", "piv-delete"},
	}
	for _, pair := range before {
		a, okA := index[pair[0]]
		b, okB := index[pair[1]]
		if !okA || !okB {
			t.Errorf("setup order misses %q or %q", pair[0], pair[1])
			continue
		}
		if a >= b {
			t.Errorf("setup order: %q must run before %q", pair[0], pair[1])
		}
	}
	for category := range secretsFamilyVerbs {
		for _, cmd := range CommandsByCategory(category) {
			if _, ok := index[cmd.Name]; !ok {
				t.Errorf("setup order misses %q", cmd.Name)
			}
		}
	}
}
