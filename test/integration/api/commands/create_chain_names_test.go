package commands

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// chainIdentifiers are the literal names the create chains share; the
// runner derives a per-transport value from each.
var chainIdentifiers = []string{"it-tenant", "it-user", "it-user@example.com", "it-oidc", "it-credential"}

// expectedChainName is the per-transport form of a chain identifier.
func expectedChainName(base string, p ProtocolType, runID int64) string {
	if local, ok := strings.CutSuffix(base, "@example.com"); ok {
		return fmt.Sprintf("%s-%s-%d@example.com", local, p, runID)
	}
	return fmt.Sprintf("%s-%s-%d", base, p, runID)
}

// resolvedChainNames returns, for each chain identifier cmd carries, the
// value commandOverrides resolves it to on protocol p.
func resolvedChainNames(cmd CommandDefinition, overrides map[string]string) map[string]string {
	out := map[string]string{}
	for _, arg := range append(slices.Clone(cmd.RequiredArgs), cmd.OptionalArgs...) {
		if !slices.Contains(chainIdentifiers, arg.Value) {
			continue
		}
		key := arg.Flag
		if arg.IsPositional {
			key = arg.Description
		}
		value, ok := overrides[key]
		if !ok {
			value = arg.Value
		}
		out[arg.Value] = value
	}
	return out
}

// TestCreateChains_PerTransportNames pins that the tenant, user, oidc and
// credential create chains run on every server transport: each transport
// creates its own name, every verb of a chain acts on its create verb's
// name, and embedded names the subsystem it lacks.
func TestCreateChains_PerTransportNames(t *testing.T) {
	chains := []struct {
		create string
		verbs  []string
		reason string
	}{
		{"tenant-create", []string{"tenant-show", "tenant-update-entitlements", "tenant-update-quotas", "tenant-delete"}, ReasonEmbeddedNoTenant},
		{"user-register", []string{"user-get", "user-update", "user-disable", "user-enable", "user-credentials", "user-bind-cert", "user-delete"}, ReasonEmbeddedNoUser},
		{"oidc-create", []string{"oidc-import", "oidc-get", "oidc-token", "oidc-delete"}, ReasonEmbeddedNoOIDC},
		{"credential-submit", nil, ReasonEmbeddedNoCredential},
	}
	all := AllCommands()
	index := map[string]int{}
	byName := map[string]CommandDefinition{}
	for i, cmd := range all {
		index[cmd.Name] = i
		byName[cmd.Name] = cmd
	}
	runner := &TestRunner{}
	dir := t.TempDir()
	const runID = 1

	for _, chain := range chains {
		createDef, ok := byName[chain.create]
		if !ok {
			t.Fatalf("no command %s", chain.create)
		}
		for _, name := range append([]string{chain.create}, chain.verbs...) {
			cmd, ok := byName[name]
			if !ok {
				t.Errorf("no command %s", name)
				continue
			}
			if name != chain.create {
				if !slices.Contains(cmd.SetupSteps, chain.create) {
					t.Errorf("%s: SetupSteps %v do not name %s", name, cmd.SetupSteps, chain.create)
				}
				for _, step := range cmd.SetupSteps {
					if i, ok := index[step]; !ok || i >= index[name] {
						t.Errorf("%s: setup step %s does not come earlier in AllCommands", name, step)
					}
				}
			}

			argvs := map[ProtocolType]string{}
			for _, p := range serverTransports {
				// (c) the cell runs on every server transport.
				if reason, skip := MatrixSkipReason(cmd, p, nil); skip {
					t.Errorf("%s on %s skips: %s", name, p, reason)
				}
				overrides := commandOverrides(cmd, p, runID, uniqueKeyIDs(runID), dir)
				argv := strings.Join(runner.BuildCommandArgs(cmd, overrides), " ")
				argvs[p] = argv
				names := resolvedChainNames(cmd, overrides)
				if len(names) == 0 {
					t.Errorf("%s carries no chain identifier", name)
				}
				// (a) every chain identifier carries the protocol name.
				for base, got := range names {
					if want := expectedChainName(base, p, runID); got != want {
						t.Errorf("%s on %s: %s resolves to %q, want %q", name, p, base, got, want)
					}
					if !strings.Contains(argv, got) {
						t.Errorf("%s on %s: argv %q lacks %q", name, p, argv, got)
					}
				}
				// (b) every verb acts on the create verb's identifier.
				created := resolvedChainNames(createDef, commandOverrides(createDef, p, runID, uniqueKeyIDs(runID), dir))
				for base, got := range names {
					if want, ok := created[base]; !ok || got != want {
						t.Errorf("%s on %s: %s = %q, create verb %s has %q", name, p, base, got, chain.create, want)
					}
				}
			}
			for i, p := range serverTransports {
				for _, q := range serverTransports[i+1:] {
					if argvs[p] == argvs[q] {
						t.Errorf("%s: %s and %s build the same argv %q", name, p, q, argvs[p])
					}
				}
			}

			if reason, skip := MatrixSkipReason(cmd, ProtocolEmbedded, nil); !skip || reason != chain.reason {
				t.Errorf("%s on embedded: skip=%v reason=%q, want %q", name, skip, reason, chain.reason)
			}
		}
	}
}
