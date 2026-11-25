//go:build integration

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

package integration

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/test/integration/api/commands"
)

// Skip reasons of the secrets cells that cannot run in the integration
// stack (row #2321 slice d).
const (
	skipPasskey = "needs a FIDO2 security key attached to the CLI host; " +
		"the integration stack has none"
	skipRecoveryCode = "the vault was initialized before this run, so its " +
		"one-time recovery code was never shown to the test"
	skipEmbeddedSession = "the embedded transport starts a fresh in-process " +
		"server per invocation, so the vault session opened by " +
		"\"password unlock\" does not outlive that command"
	skipPIVToken = "the backend needs a physical PIV token for this verb"
)

// secretsState carries what one transport's workflow leaves for the next:
// the vault's current one-time recovery code.
type secretsState struct {
	recoveryCode string
}

// secretsWorkflow runs the password, pin and piv commands of the CLI
// matrix on one transport, each after the steps it needs
// (commands.SecretsSetupOrder).
type secretsWorkflow struct {
	runner   *commands.TestRunner
	protocol commands.ProtocolType
	state    *secretsState
	// variant is the index of the override set the last passing cell used.
	variant int
}

// TestCLISecretsMatrix runs every password, pin and piv verb on every CLI
// transport through cfg.CreateClient; a cell that cannot run names why.
func TestCLISecretsMatrix(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)
	runner = runner.WithBackend("software")
	state := &secretsState{}

	for _, protocol := range commands.CLIProtocols() {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}
			if gap := runnerIdentityGap(runner, protocol); gap != "" {
				t.Fatalf("[%s] the secrets workflows need an authenticated caller: %s", protocol, gap)
			}
			w := &secretsWorkflow{runner: runner, protocol: protocol, state: state}
			t.Run("password", w.family(commands.CategoryPassword, w.password))
			t.Run("pin", w.family(commands.CategoryPIN, w.pin))
			t.Run("piv", w.family(commands.CategoryPIV, w.piv))
		})
	}
}

// runnerIdentityGap returns why the runner cannot authenticate on protocol, or
// "" when it can: a remote transport needs a client certificate and key that
// exist, or a token; the embedded transport runs in-process and needs none.
func runnerIdentityGap(r *commands.TestRunner, protocol commands.ProtocolType) string {
	if protocol == commands.ProtocolEmbedded || r.Token != "" {
		return ""
	}
	if r.ClientCert == "" || r.ClientKey == "" {
		return "no client certificate and key (KEYSTORE_TLS_CERT, KEYSTORE_TLS_KEY) and no token (KEYSTORE_TOKEN)"
	}
	for _, f := range []string{r.ClientCert, r.ClientKey} {
		if _, err := os.Stat(f); err != nil {
			return "client credential file unreadable: " + err.Error()
		}
	}
	return ""
}

// authRefusal reports whether a command's output is the server refusing an
// unauthenticated or unauthorized caller.
func authRefusal(output string) bool {
	out := strings.ToLower(output)
	for _, marker := range []string{
		"unauthenticated", "permissiondenied", "permission denied",
		"401 unauthorized", "403 forbidden", "authentication required",
	} {
		if strings.Contains(out, marker) {
			return true
		}
	}
	return false
}

// family wraps a workflow so a transport that lacks the family's services
// (commands.SecretsWorkflowSkip) is skipped with its reason before any cell
// runs.
func (w *secretsWorkflow) family(category commands.CommandCategory, run func(*testing.T)) func(*testing.T) {
	return func(t *testing.T) {
		if reason, skip := commands.SecretsWorkflowSkip(category, w.protocol); skip {
			t.Skip(reason)
		}
		run(t)
	}
}

// command returns the matrix command name.
func (w *secretsWorkflow) command(t *testing.T, name string) commands.CommandDefinition {
	t.Helper()
	cmd, ok := commands.SecretsCommand(name)
	if !ok {
		t.Fatalf("no secrets command %q", name)
	}
	return cmd
}

// exec runs a command outside a cell: a setup or cleanup step.
func (w *secretsWorkflow) exec(t *testing.T, cmd commands.CommandDefinition, overrides map[string]string) *commands.TestResult {
	t.Helper()
	result := w.runner.RunCommandTest(t, w.protocol, cmd, overrides)
	if !result.Passed {
		t.Logf("[%s] %s: %s\nstdout: %s\nstderr: %s", w.protocol, cmd.Name, result.Message, result.Stdout, result.Stderr)
	}
	return result
}

// cell runs one matrix cell as a subtest and returns its stdout and whether
// it ran and passed. Each override set is tried in turn; the first that
// passes is the cell's result.
func (w *secretsWorkflow) cell(t *testing.T, name string, variants ...map[string]string) (string, bool) {
	t.Helper()
	cmd := w.command(t, name)
	if len(variants) == 0 {
		variants = []map[string]string{nil}
	}
	var stdout string
	passed := false
	t.Run(name, func(t *testing.T) {
		var last *commands.TestResult
		for i, overrides := range variants {
			last = w.exec(t, cmd, overrides)
			if last.Passed {
				stdout, passed, w.variant = last.Stdout, true, i
				return
			}
		}
		if authRefusal(last.Stdout + last.Stderr) {
			t.Fatalf("[%s] %s was refused as unauthenticated or unauthorized: %s\nstderr: %s",
				w.protocol, name, last.Message, last.Stderr)
		}
		w.skipKnown(t, cmd, last)
		t.Fatalf("[%s] %s failed: %s\nstdout: %s\nstderr: %s",
			w.protocol, name, last.Message, last.Stdout, last.Stderr)
	})
	return stdout, passed
}

// skipKnown skips a failed cell whose failure is one of the named
// environment limits rather than a defect.
func (w *secretsWorkflow) skipKnown(t *testing.T, cmd commands.CommandDefinition, result *commands.TestResult) {
	t.Helper()
	output := strings.ToLower(result.Stdout + result.Stderr)
	if cmd.Category == commands.CategoryPassword && w.protocol == commands.ProtocolEmbedded &&
		strings.Contains(output, "locked") {
		t.Skip(skipEmbeddedSession)
	}
	if cmd.Category == commands.CategoryPIV &&
		(strings.Contains(output, "physical") || strings.Contains(output, "smart card")) {
		t.Skipf("%s: %s", skipPIVToken, strings.TrimSpace(result.Stderr))
	}
}

// skipCell records a cell that cannot run, with its reason.
func skipCell(t *testing.T, name, reason string) {
	t.Helper()
	t.Run(name, func(t *testing.T) { t.Skip(reason) })
}

// setupID returns the "id" a setup cell printed. A setup cell that exited
// zero must print valid JSON with a nonempty ID; when it does not, the
// workflow fails here, so the dependent cells it then skips are never a
// silent loss of coverage. A cell that failed already failed its subtest.
func (w *secretsWorkflow) setupID(t *testing.T, name, out string, passed bool) string {
	t.Helper()
	return w.setupField(t, name, "id", out, passed)
}

// setupField is setupID for any JSON field: a passing producer cell must
// print the field nonempty, or the workflow fails here with its stdout.
func (w *secretsWorkflow) setupField(t *testing.T, name, field, out string, passed bool) string {
	t.Helper()
	if !passed {
		return ""
	}
	value := jsonValue(out, field)
	if value == "" {
		t.Errorf("[%s] %s exited zero without a JSON response carrying a nonempty %s\nstdout: %s",
			w.protocol, name, field, out)
	}
	return value
}

func (w *secretsWorkflow) password(t *testing.T) {
	w.cell(t, "password-vault-status")

	// Setup: the first enrollment initializes the vault and shows the
	// recovery code once. A vault that already exists unlocks instead.
	unlock := w.command(t, "password-unlock")
	if !w.exec(t, unlock, nil).Passed {
		first := w.command(t, "password-vault-enroll")
		result := w.exec(t, first, map[string]string{
			"passphrase": commands.SecretsVaultPassphrase,
			"label":      "it-matrix-first",
		})
		if !result.Passed {
			t.Fatalf("[%s] vault initialization failed: %s", w.protocol, result.Message)
		}
		w.state.recoveryCode = w.setupField(t, "password-vault-enroll", "recoverycode", result.Stdout, true)
	}
	skipCell(t, "password-unlock-passkey", skipPasskey)
	if _, ok := w.cell(t, "password-unlock"); !ok {
		return
	}
	w.cell(t, "password-status")
	w.cell(t, "password-access-mode")

	out, added := w.cell(t, "password-add")
	entryID := w.setupID(t, "password-add", out, added)
	entry := map[string]string{commands.ArgEntryID: entryID}
	if entryID != "" {
		w.cell(t, "password-get", entry)
		w.cell(t, "password-list")
		w.cell(t, "password-update", entry)
	} else {
		for _, name := range []string{"password-get", "password-list", "password-update"} {
			skipCell(t, name, "needs the entry ID \"password add\" returns, and that cell failed")
		}
	}
	w.cell(t, "password-generate")

	skipCell(t, "password-vault-enroll-passkey", skipPasskey)
	out, enrolled := w.cell(t, "password-vault-enroll")
	if factorID := w.setupID(t, "password-vault-enroll", out, enrolled); factorID != "" {
		out, rotated := w.cell(t, "password-vault-rotate", map[string]string{"factor-id": factorID})
		if rotatedID := w.setupID(t, "password-vault-rotate", out, rotated); rotatedID != "" {
			w.cell(t, "password-vault-remove", map[string]string{"factor-id": rotatedID})
		} else {
			skipCell(t, "password-vault-remove", "needs the factor ID \"password vault rotate\" returns, and that cell failed")
		}
	} else {
		skipCell(t, "password-vault-rotate", "needs the factor ID \"password vault enroll\" returns, and that cell failed")
		skipCell(t, "password-vault-remove", "needs the factor ID \"password vault enroll\" returns, and that cell failed")
	}

	skipCell(t, "password-vault-recover-passkey", skipPasskey)
	if w.state.recoveryCode == "" {
		skipCell(t, "password-vault-recover", skipRecoveryCode)
	} else if out, ok := w.cell(t, "password-vault-recover",
		map[string]string{"recovery-code": w.state.recoveryCode}); ok {
		// The old code stops working; the next transport uses the new one.
		w.state.recoveryCode = w.setupField(t, "password-vault-recover", "recoverycode", out, true)
		if recoveredID := jsonValue(out, "id"); recoveredID != "" {
			w.exec(t, w.command(t, "password-vault-remove"), map[string]string{"factor-id": recoveredID})
		}
	}

	if entryID != "" {
		w.cell(t, "password-delete", entry)
	} else {
		skipCell(t, "password-delete", "needs the entry ID \"password add\" returns, and that cell failed")
	}
	w.cell(t, "password-lock")
}

func (w *secretsWorkflow) pin(t *testing.T) {
	soChange := w.command(t, "pin-so-change")
	restoreSO := func() {
		if !w.exec(t, soChange, map[string]string{
			"current-pin": commands.SecretsSOPINAlt,
			"new-pin":     commands.SecretsSOPIN,
		}).Passed {
			t.Fatalf("[%s] restoring the SO PIN failed", w.protocol)
		}
	}

	// A first so-set needs no current PIN; on a token whose SO PIN an
	// earlier transport set, so-set moves it with the current PIN and the
	// workflow moves it back.
	_, ok := w.cell(t, "pin-so-set", nil, map[string]string{
		"current-pin": commands.SecretsSOPIN,
		"new-pin":     commands.SecretsSOPINAlt,
	})
	if !ok {
		return
	}
	if w.variant == 1 {
		restoreSO()
	}
	w.cell(t, "pin-so-verify")
	if _, changed := w.cell(t, "pin-so-change"); changed {
		restoreSO()
	}

	if _, ok := w.cell(t, "pin-user-set"); !ok {
		return
	}
	w.cell(t, "pin-user-verify")
	if _, changed := w.cell(t, "pin-user-change"); changed {
		if !w.exec(t, w.command(t, "pin-user-change"), map[string]string{
			"current-pin": commands.SecretsUserPINAlt,
			"new-pin":     commands.SecretsUserPIN,
		}).Passed {
			t.Fatalf("[%s] restoring the user PIN failed", w.protocol)
		}
	}
	w.cell(t, "pin-lockout")
	w.cell(t, "pin-lockout-reset")
}

func (w *secretsWorkflow) piv(t *testing.T) {
	remove := w.command(t, "piv-delete")
	clean := func() {
		for _, slot := range []string{commands.SecretsPIVSlot, commands.SecretsPIVStoreSlot, commands.SecretsPIVImportSlot} {
			w.exec(t, remove, map[string]string{commands.ArgPIVSlot: slot})
		}
	}
	// Setup: empty slots left by an earlier transport or run.
	clean()
	t.Cleanup(clean)

	w.cell(t, "piv-list")
	if _, ok := w.cell(t, "piv-generate"); !ok {
		for _, name := range []string{"piv-get", "piv-csr", "piv-export", "piv-store", "piv-import", "piv-delete"} {
			skipCell(t, name, "needs the key \"piv generate\" creates, and that cell failed")
		}
		return
	}
	w.cell(t, "piv-get")
	w.cell(t, "piv-csr")
	out, exported := w.cell(t, "piv-export")

	certFile := ""
	if block, _ := pem.Decode([]byte(out[max(0, strings.Index(out, "-----BEGIN")):])); exported && block != nil {
		certFile = filepath.Join(t.TempDir(), "piv.pem")
		if err := os.WriteFile(certFile, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatalf("write %s: %v", certFile, err)
		}
	}
	if certFile == "" {
		skipCell(t, "piv-store", "needs the certificate \"piv export\" prints, and that cell failed")
		skipCell(t, "piv-import", "needs the certificate \"piv export\" prints, and that cell failed")
	} else {
		w.cell(t, "piv-store", map[string]string{"cert-file": certFile})
		w.cell(t, "piv-import", map[string]string{"cert-file": certFile})
	}
	w.cell(t, "piv-delete")
}

// jsonValue returns the first string or number in the JSON object of output
// whose key, lower-cased and without '_' or '-', is name.
func jsonValue(output, name string) string {
	start, end := strings.Index(output, "{"), strings.LastIndex(output, "}")
	if start < 0 || end <= start {
		return ""
	}
	var doc any
	if err := json.Unmarshal([]byte(output[start:end+1]), &doc); err != nil {
		return ""
	}
	return findJSONValue(doc, name)
}

func findJSONValue(doc any, name string) string {
	switch v := doc.(type) {
	case map[string]any:
		for key, value := range v {
			norm := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(key))
			if norm != name {
				continue
			}
			switch s := value.(type) {
			case string:
				return s
			case float64:
				return strconv.FormatFloat(s, 'f', -1, 64)
			}
		}
		for _, value := range v {
			if found := findJSONValue(value, name); found != "" {
				return found
			}
		}
	case []any:
		for _, value := range v {
			if found := findJSONValue(value, name); found != "" {
				return found
			}
		}
	}
	return ""
}
