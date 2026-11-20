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

// TestCLIProtocols_CoversEverySDKTransport pins the SDK transport list of
// docs/SPEC.md (cli-protocol-matrix): embedded, unix, gRPC, QUIC, REST, MCP.
func TestCLIProtocols_CoversEverySDKTransport(t *testing.T) {
	want := []ProtocolType{ProtocolEmbedded, ProtocolUnix, ProtocolGRPC, ProtocolQUIC, ProtocolREST, ProtocolMCP}
	got := CLIProtocols()
	for _, p := range want {
		if !slices.Contains(got, p) {
			t.Errorf("CLIProtocols() = %v, missing %s", got, p)
		}
	}
	if len(got) != len(want) {
		t.Errorf("CLIProtocols() = %v, want exactly %v", got, want)
	}
}

// TestMatrix_EverySkippedCellHasReason walks every (family, transport) cell
// of the matrix: a cell either runs at least one command or names why it
// is skipped.
func TestMatrix_EverySkippedCellHasReason(t *testing.T) {
	allTags := []string{"frost", "fido2"}
	for _, family := range CommandFamilies() {
		for _, protocol := range CLIProtocols() {
			cell := MatrixCellFor(family, protocol, allTags)
			if cell.Runs > 0 {
				continue
			}
			if cell.Reason == "" {
				t.Errorf("cell (%s, %s) runs no command and names no reason", family, protocol)
			}
		}
	}
}

// TestMatrix_SkipReasons checks the per-command skip decisions.
func TestMatrix_SkipReasons(t *testing.T) {
	setup := CommandDefinition{Name: "x", Category: CategoryCA, RequiresSetup: true}
	if r, skip := SkipReason(setup, ProtocolMCP, nil); !skip || r == "" {
		t.Errorf("RequiresSetup command: skip=%v reason=%q", skip, r)
	}

	tagged := CommandDefinition{Name: "y", Category: CategoryFrost, BuildTags: []string{"frost"}}
	if r, skip := SkipReason(tagged, ProtocolEmbedded, nil); !skip || r == "" {
		t.Errorf("tagged command without tag: skip=%v reason=%q", skip, r)
	}
	if _, skip := SkipReason(tagged, ProtocolEmbedded, []string{"frost"}); skip {
		t.Error("tagged command with its tag must run")
	}

	plain := CommandDefinition{Name: "z", Category: CategoryKey}
	for _, p := range CLIProtocols() {
		if r, skip := SkipReason(plain, p, nil); skip {
			t.Errorf("key command skipped on %s: %s", p, r)
		}
	}
}

// TestMatrix_AccountFamilies checks that every tenant, user, auth, credential
// and oidc subcommand of row #2321 slice (c) has a definition, that each
// family is a matrix row, and that every cell of it runs or names a reason.
func TestMatrix_AccountFamilies(t *testing.T) {
	want := map[CommandCategory][]string{
		CategoryTenant: {
			"tenant create", "tenant list", "tenant show",
			"tenant update-entitlements", "tenant update-quotas", "tenant delete",
		},
		CategoryUser: {
			"user register", "user login", "user list", "user get", "user update",
			"user disable", "user enable", "user status", "user credentials",
			"user bind-cert", "user delete", "user invite redeem",
		},
		CategoryAuth: {
			"auth login", "auth factor list", "auth factor add", "auth factor remove",
			"auth factor rotate", "auth factor relabel",
		},
		CategoryCredential: {
			"credential submit", "credential list", "credential strategy", "credential rotate",
		},
		CategoryOIDC: {
			"oidc templates", "oidc create", "oidc import", "oidc list", "oidc get",
			"oidc token", "oidc refresh", "oidc login", "oidc delete",
		},
	}
	have := map[string]CommandDefinition{}
	for _, cmd := range AllCommands() {
		have[strings.Join(cmd.Command, " ")] = cmd
	}
	for family, cmds := range want {
		if !slices.Contains(CommandFamilies(), family) {
			t.Errorf("family %s is not a matrix row", family)
		}
		for _, c := range cmds {
			def, ok := have[c]
			if !ok {
				t.Errorf("no definition for %q", c)
				continue
			}
			if def.Category != family {
				t.Errorf("%q: category %s, want %s", c, def.Category, family)
			}
		}
		for _, p := range CLIProtocols() {
			cell := MatrixCellFor(family, p, nil)
			if cell.Runs == 0 && cell.Reason == "" {
				t.Errorf("cell (%s, %s) neither runs nor names a reason", family, p)
			}
		}
	}

	skipped := CommandDefinition{Name: "w", Category: CategoryOIDC, Skip: "browser flow"}
	if r, skip := SkipReason(skipped, ProtocolREST, nil); !skip || r != "browser flow" {
		t.Errorf("Skip command: skip=%v reason=%q", skip, r)
	}
}

// TestRunCommandWithProtocol_EmbeddedArgs checks the embedded prefix:
// one --transport embedded and the runner's key directory.
func TestRunCommandWithProtocol_EmbeddedArgs(t *testing.T) {
	r := &TestRunner{KeyDir: "/tmp/k"}
	got := r.protocolArgs(ProtocolEmbedded, []string{"--transport", "embedded", "frost", "list"})
	want := []string{"--key-dir", "/tmp/k", "--transport", "embedded", "frost", "list"}
	if !slices.Equal(got, want) {
		t.Errorf("protocolArgs(embedded) = %v, want %v", got, want)
	}

	got = r.protocolArgs(ProtocolEmbedded, []string{"version"})
	want = []string{"--transport", "embedded", "--key-dir", "/tmp/k", "version"}
	if !slices.Equal(got, want) {
		t.Errorf("protocolArgs(embedded) = %v, want %v", got, want)
	}

	r.MCPAddr = "localhost:9444"
	got = r.protocolArgs(ProtocolMCP, []string{"version"})
	want = []string{"--server", "mcp://localhost:9444", "version"}
	if !slices.Equal(got, want) {
		t.Errorf("protocolArgs(mcp) = %v, want %v", got, want)
	}
}
