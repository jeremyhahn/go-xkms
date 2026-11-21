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

// TestCompiledTags checks that the matrix tag set names every optional
// family the CLI binary was built with, fido2 included (#2321 gap 5), and
// leaves out the ones it lacks.
func TestCompiledTags(t *testing.T) {
	all := CompiledTags(func(string) bool { return true })
	for _, tag := range []string{"integration", "frost", "fido2"} {
		if !slices.Contains(all, tag) {
			t.Errorf("CompiledTags(all) = %v, missing %s", all, tag)
		}
	}

	none := CompiledTags(func(string) bool { return false })
	if !slices.Equal(none, []string{"integration"}) {
		t.Errorf("CompiledTags(none) = %v, want [integration]", none)
	}

	onlyFIDO2 := CompiledTags(func(command string) bool { return command == "fido2" })
	if !slices.Contains(onlyFIDO2, "fido2") || slices.Contains(onlyFIDO2, "frost") {
		t.Errorf("CompiledTags(fido2 only) = %v", onlyFIDO2)
	}

	// With fido2 compiled in, every FIDO2 verb that needs an authenticator
	// names that gap; list-devices runs (it lists none).
	for _, cmd := range FIDO2Commands() {
		r, skip := MatrixSkipReason(cmd, ProtocolUnix, all)
		if cmd.Name == "fido2-list-devices" {
			if skip {
				t.Errorf("fido2-list-devices skipped with fido2 compiled: %s", r)
			}
			continue
		}
		if !skip || r != skipFIDO2 {
			t.Errorf("%s: skip=%v reason=%q, want %q", cmd.Name, skip, r, skipFIDO2)
		}
	}

	// Every tag a command definition requires is either probed or always on,
	// so no cell is skipped only because the tag set forgot it.
	known := CompiledTags(func(string) bool { return true })
	for _, cmd := range AllCommands() {
		for _, tag := range cmd.BuildTags {
			if !slices.Contains(known, tag) && tag != "gui" {
				t.Errorf("%s requires tag %q, which CompiledTags never reports", cmd.Name, tag)
			}
		}
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

	// The integration server serves MCP over TLS: the runner must use
	// mcps:// and pass the test CA, or the SDK speaks plaintext HTTP.
	r.MCPAddr = "localhost:9444"
	r.TLSCACert = "/etc/xkms/certs/ca.crt"
	got = r.protocolArgs(ProtocolMCP, []string{"version"})
	want = []string{"--server", "mcps://localhost:9444", "--tls-ca", "/etc/xkms/certs/ca.crt", "version"}
	if !slices.Equal(got, want) {
		t.Errorf("protocolArgs(mcp) = %v, want %v", got, want)
	}
}

// TestCACommands_EmbeddedCellNamesNoCA checks the CA family on the embedded
// transport: the embedded service (sdk/go/embedded.go) installs no CA, so
// every CA cell there is skipped with ReasonEmbeddedNoCA, while the server
// transports still run the verbs that need no setup.
func TestCACommands_EmbeddedCellNamesNoCA(t *testing.T) {
	cmds := CACommands()
	if len(cmds) == 0 {
		t.Fatal("CACommands() is empty")
	}
	for _, def := range cmds {
		r, skip := MatrixSkipReason(def, ProtocolEmbedded, nil)
		if !skip || r != ReasonEmbeddedNoCA {
			t.Errorf("(ca, embedded) %s: skip=%v reason=%q, want %q", def.Name, skip, r, ReasonEmbeddedNoCA)
		}
		for _, p := range []ProtocolType{ProtocolUnix, ProtocolREST, ProtocolGRPC, ProtocolQUIC, ProtocolMCP} {
			r, skip := MatrixSkipReason(def, p, nil)
			if !def.RequiresSetup && skip {
				t.Errorf("(ca, %s) %s skipped: %s", p, def.Name, r)
			}
			if r == ReasonEmbeddedNoCA {
				t.Errorf("(ca, %s) %s carries the embedded reason", p, def.Name)
			}
		}
	}
}
