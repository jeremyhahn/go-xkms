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

// sliceEVerbs lists every xkmsctl verb of #2321 slice (e) by family: each
// must have a command definition, and so a cell on every transport.
var sliceEVerbs = map[CommandCategory][][]string{
	CategoryPlatform: {
		{"platform", "put"}, {"platform", "get"}, {"platform", "delete"},
		{"platform", "list"}, {"platform", "reseal"}, {"platform", "status"},
	},
	CategoryServer:     {{"status"}},
	CategoryAlgorithms: {{"algorithms"}},
	CategoryCluster: {
		{"cluster", "status"}, {"cluster", "members"}, {"cluster", "add"}, {"cluster", "remove"},
	},
	CategoryRebalance: {
		{"rebalance", "stats"}, {"rebalance", "plan"}, {"rebalance", "execute"}, {"rebalance", "report"},
	},
	CategoryBootstrap: {
		{"bootstrap", "auto"}, {"bootstrap", "show-keys"},
		{"bootstrap", "noise", "generate-key"}, {"bootstrap", "noise", "show-key"},
		{"bootstrap", "noise", "show-spki-pin"}, {"bootstrap", "noise", "generate-p256-key"},
		{"bootstrap", "noise", "show-p256-key"},
		{"bootstrap", "dane", "generate-tlsa"}, {"bootstrap", "dane", "verify-tlsa"},
		{"bootstrap", "dane", "show-tlsa"},
		{"bootstrap", "spki", "show-pin"},
	},
}

// TestMatrix_SliceEFamilies: every slice (e) verb has a definition in its
// family, the family is in the matrix, and on every transport the verb runs
// or names why it cannot.
func TestMatrix_SliceEFamilies(t *testing.T) {
	allTags := []string{"frost", "fido2"}
	for family, verbs := range sliceEVerbs {
		if !slices.Contains(CommandFamilies(), family) {
			t.Errorf("family %s is not in CommandFamilies", family)
		}
		defs := CommandsByCategory(family)
		for _, verb := range verbs {
			var found []CommandDefinition
			for _, def := range defs {
				if slices.Equal(def.Command, verb) {
					found = append(found, def)
				}
			}
			if len(found) == 0 {
				t.Errorf("family %s: no command definition for %v", family, verb)
				continue
			}
			for _, def := range found {
				for _, p := range CLIProtocols() {
					if r, skip := MatrixSkipReason(def, p, allTags); skip && r == "" {
						t.Errorf("(%s, %s) %s skipped without a reason", family, p, def.Name)
					}
				}
			}
		}
	}
}

// TestMatrix_SliceETransports pins which transports each slice (e) family
// runs on, and the reason every other cell names.
func TestMatrix_SliceETransports(t *testing.T) {
	allTags := []string{"frost", "fido2"}
	runsOn := func(family CommandCategory, p ProtocolType) MatrixCell {
		return MatrixCellFor(family, p, allTags)
	}
	for _, p := range CLIProtocols() {
		for _, family := range []CommandCategory{CategoryPlatform, CategoryServer, CategoryAlgorithms} {
			if cell := runsOn(family, p); cell.Runs != len(sliceEVerbs[family]) {
				t.Errorf("(%s, %s): %d of %d verbs run (%s)", family, p, cell.Runs, len(sliceEVerbs[family]), cell.Reason)
			}
		}
		for _, family := range []CommandCategory{CategoryCluster, CategoryRebalance} {
			cell := runsOn(family, p)
			switch p {
			case ProtocolUnix, ProtocolGRPC:
				if cell.Runs != len(sliceEVerbs[family]) {
					t.Errorf("(%s, %s): %d of %d verbs run (%s)", family, p, cell.Runs, len(sliceEVerbs[family]), cell.Reason)
				}
			default:
				if cell.Runs != 0 || !strings.Contains(cell.Reason, ReasonQRDBControlPlane) {
					t.Errorf("(%s, %s): runs=%d reason=%q, want the control-plane reason", family, p, cell.Runs, cell.Reason)
				}
			}
		}

		// Bootstrap: show-keys is an SDK call and runs everywhere; the local
		// verbs run once, on the embedded cell, and name the reason elsewhere.
		for _, def := range CommandsByCategory(CategoryBootstrap) {
			r, skip := MatrixSkipReason(def, p, allTags)
			sdk := slices.Equal(def.Command, []string{"bootstrap", "show-keys"})
			switch {
			case sdk && skip:
				t.Errorf("(bootstrap, %s) %s skipped: %s", p, def.Name, r)
			case !sdk && def.Unsupported == "" && p == ProtocolEmbedded && skip:
				t.Errorf("(bootstrap, %s) %s skipped: %s", p, def.Name, r)
			case !sdk && p != ProtocolEmbedded && r != ReasonNoSDKTransport && def.Unsupported == "":
				t.Errorf("(bootstrap, %s) %s: reason %q, want %q", p, def.Name, r, ReasonNoSDKTransport)
			}
		}
	}
}

// TestMatrix_WorkflowCommands: a workflow command is counted as a run in the
// matrix but left out of the standalone run, which names its workflow.
func TestMatrix_WorkflowCommands(t *testing.T) {
	wf := CommandDefinition{Name: "w", Category: CategoryPlatform, Workflow: "TestCLIPlatformMatrix"}
	if _, skip := MatrixSkipReason(wf, ProtocolREST, nil); skip {
		t.Error("workflow command must count as a matrix run")
	}
	if r, skip := SkipReason(wf, ProtocolREST, nil); !skip || !strings.Contains(r, "TestCLIPlatformMatrix") {
		t.Errorf("standalone run of a workflow command: skip=%v reason=%q", skip, r)
	}
	only := CommandDefinition{Name: "o", Category: CategoryCluster, Transports: []ProtocolType{ProtocolUnix}, TransportSkip: "because"}
	if r, skip := MatrixSkipReason(only, ProtocolMCP, nil); !skip || r != "because" {
		t.Errorf("transport-restricted command on mcp: skip=%v reason=%q", skip, r)
	}
	if _, skip := MatrixSkipReason(only, ProtocolUnix, nil); skip {
		t.Error("transport-restricted command must run on its transport")
	}
	never := CommandDefinition{Name: "n", Category: CategoryBootstrap, Unsupported: "no DNS"}
	if r, skip := MatrixSkipReason(never, ProtocolEmbedded, nil); !skip || r != "no DNS" {
		t.Errorf("unsupported command: skip=%v reason=%q", skip, r)
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
