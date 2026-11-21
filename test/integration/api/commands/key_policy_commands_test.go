//go:build integration

package commands

import (
	"strings"
	"testing"
)

// keyPolicyVerbs is the verb set row #2321 slice (f) requires in the CLI
// matrix: the key lifecycle verbs beyond generate/list/info/sign/verify/delete
// and the full TPM policy verb set.
var keyPolicyVerbs = [][]string{
	{"key", "rotate"},
	{"key", "import"},
	{"key", "export"},
	{"key", "get-import-params"},
	{"key", "wrap"},
	{"key", "unwrap"},
	{"key", "attest"},
	{"key", "versions"},
	{"key", "rotate-all"},
	{"key", "version", "enable"},
	{"key", "version", "disable"},
	{"key", "version", "retire"},
	{"key", "version", "enable-all"},
	{"key", "version", "disable-all"},
	{"key", "policy"},
	{"tpm", "policy", "create"},
	{"tpm", "policy", "list"},
	{"tpm", "policy", "get"},
	{"tpm", "policy", "verify"},
	{"tpm", "policy", "update"},
	{"tpm", "policy", "objects"},
	{"tpm", "policy", "revoke"},
	{"tpm", "policy", "describe"},
	{"tpm", "policy", "auto-unseal"},
	{"tpm", "policy", "delete"},
	{"tpm", "authority", "rotate"},
}

func TestKeyPolicyVerbsDeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, def := range AllCommands() {
		declared[strings.Join(def.Command, " ")] = true
	}
	for _, verb := range keyPolicyVerbs {
		if !declared[strings.Join(verb, " ")] {
			t.Errorf("xkmsctl %s has no command definition in the CLI matrix", strings.Join(verb, " "))
		}
	}
}

// TestKeyPolicySetupDeclared fails when a key or policy command needs setup
// but names no setup step (it would only ever be skipped), or names a step
// that does not run before it in the one ordered pass.
func TestKeyPolicySetupDeclared(t *testing.T) {
	position := map[string]int{}
	all := AllCommands()
	for i, def := range all {
		position[def.Name] = i
	}
	lastPolicy := ""
	for i, def := range all {
		if def.Category != CategoryKey && def.Category != CategoryPolicy {
			continue
		}
		if def.Category == CategoryPolicy {
			lastPolicy = def.Name
		}
		if def.RequiresSetup && len(def.SetupSteps) == 0 {
			t.Errorf("%s requires setup but declares no SetupSteps", def.Name)
		}
		for _, step := range def.SetupSteps {
			at, ok := position[step]
			if !ok {
				t.Errorf("%s: setup step %q is not a declared command", def.Name, step)
				continue
			}
			if at >= i {
				t.Errorf("%s: setup step %q runs after it", def.Name, step)
			}
		}
	}
	if lastPolicy != "tpm-policy-delete" {
		t.Errorf("tpm-policy-delete must be the last policy command, got %s", lastPolicy)
	}
}

// TestKeyPolicyCellsPerTransport checks every verb has a cell on each CLI
// transport that either runs or is skipped with a named reason, and that no
// key or policy command is skipped for RequiresSetup alone.
func TestKeyPolicyCellsPerTransport(t *testing.T) {
	tags := []string{"frost"}
	for _, protocol := range CLIProtocols() {
		for _, verb := range keyPolicyVerbs {
			joined := strings.Join(verb, " ")
			found := false
			for _, def := range AllCommands() {
				if strings.Join(def.Command, " ") != joined {
					continue
				}
				found = true
				reason, skip := SkipReason(def, protocol, tags)
				if skip && reason == "" {
					t.Errorf("(%s, %s) %s skipped without a reason", def.Category, protocol, def.Name)
				}
				if skip && def.RequiresSetup {
					t.Errorf("(%s, %s) %s skipped for setup: %s", def.Category, protocol, def.Name, reason)
				}
			}
			if !found {
				t.Errorf("(%s) xkmsctl %s has no cell", protocol, joined)
			}
		}
	}
}

// TestUnsupportedOnBackendSkipsAttest checks key attest on a backend without
// attestation becomes a named skip, and a pass is never skipped.
func TestUnsupportedOnBackendSkipsAttest(t *testing.T) {
	var attest CommandDefinition
	for _, def := range KeyCommands() {
		if def.Name == "key-attest" {
			attest = def
		}
	}
	if attest.Name == "" {
		t.Fatal("key-attest not declared")
	}
	reason, skip := unsupportedOnBackend(attest, &TestResult{Stderr: "error: attestation not supported by backend software"})
	if !skip || reason == "" {
		t.Errorf("unsupported attest not skipped with a reason: %q %v", reason, skip)
	}
	if _, skip := unsupportedOnBackend(attest, &TestResult{Passed: true}); skip {
		t.Error("passing attest skipped")
	}
	if _, skip := unsupportedOnBackend(attest, &TestResult{Stderr: "connection refused"}); skip {
		t.Error("unrelated failure skipped")
	}
}

func TestFailedSetupStep(t *testing.T) {
	def := CommandDefinition{SetupSteps: []string{"a", "b"}}
	if step, ok := failedSetupStep(def, map[string]bool{"a": true}); !ok || step != "b" {
		t.Errorf("got %q %v, want b", step, ok)
	}
	if _, ok := failedSetupStep(def, map[string]bool{"a": true, "b": true}); ok {
		t.Error("all steps passed but reported failed")
	}
}
