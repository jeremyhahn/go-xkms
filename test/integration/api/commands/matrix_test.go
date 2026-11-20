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

// TestMatrix_ACMEAndAdminFamilies checks that every acme and admin
// subcommand has a matrix cell on every transport that runs or names its
// skip reason (#2321 slice b).
func TestMatrix_ACMEAndAdminFamilies(t *testing.T) {
	want := map[string]bool{
		"acme account list": false, "acme account get": false, "acme account disable": false,
		"acme cert list": false, "acme cert get": false, "acme cert revoke": false,
		"acme eab create": false, "acme eab get": false, "acme eab delete": false, "acme eab list": false,
		"acme status": false, "acme stats": false, "acme gui": false,
		"admin create": false, "admin list": false, "admin get": false, "admin disable": false,
		"admin enable": false, "admin delete": false, "admin status": false,
	}
	for _, cmd := range AllCommands() {
		key := strings.Join(cmd.Command, " ")
		if _, ok := want[key]; !ok {
			continue
		}
		want[key] = true
		for _, p := range CLIProtocols() {
			if r, skip := SkipReason(cmd, p, nil); skip && r == "" {
				t.Errorf("%s on %s skipped without a reason", key, p)
			}
		}
	}
	for key, found := range want {
		if !found {
			t.Errorf("%s has no matrix entry", key)
		}
	}

	// Read-only admin cells run on every transport.
	for _, cmd := range AdminCommands() {
		if cmd.Name != "admin-list" && cmd.Name != "admin-status" {
			continue
		}
		for _, p := range CLIProtocols() {
			if r, skip := SkipReason(cmd, p, nil); skip {
				t.Errorf("%s skipped on %s: %s", cmd.Name, p, r)
			}
		}
	}

	explicit := CommandDefinition{Name: "w", Category: CategoryACME, Skip: "no ACME admin API"}
	if r, skip := SkipReason(explicit, ProtocolREST, nil); !skip || r != "no ACME admin API" {
		t.Errorf("explicit skip: skip=%v reason=%q", skip, r)
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
