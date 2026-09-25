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

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// resetFIDO2PolicyFlags resets all FIDO2 policy subcommand flags to their
// default values. Cobra retains flag state across Execute() calls within
// the same process, which causes test pollution when multiple tests modify
// the same flags.
func resetFIDO2PolicyFlags() {
	cmds := []*pflag.FlagSet{
		fido2Cmd.Flags(),
		fido2Cmd.PersistentFlags(),
		rpPolicyCmd.Flags(),
		rpPolicyCmd.PersistentFlags(),
		rpPolicyListCmd.Flags(),
		rpPolicySetCmd.Flags(),
		rpPolicyGetCmd.Flags(),
		rpPolicyDeleteCmd.Flags(),
		fido2ProfileCmd.Flags(),
		fido2ProfileSetCmd.Flags(),
		fido2ProfileShowCmd.Flags(),
	}
	for _, fs := range cmds {
		fs.VisitAll(func(f *pflag.Flag) {
			f.Changed = false
			_ = f.Value.Set(f.DefValue)
		})
	}
}

// setFIDO2ViperMemory sets viper config for memory-based FIDO2 storage.
func setFIDO2ViperMemory() {
	viper.Set("fido2.storage", "memory")
}

// setFIDO2ViperFile sets viper config for file-based FIDO2 storage at
// the given directory path.
func setFIDO2ViperFile(storePath string) {
	viper.Set("fido2.storage", "file")
	viper.Set("fido2.storage_path", storePath)
}

// resetFIDO2Viper clears FIDO2 viper configuration keys set by test helpers.
func resetFIDO2Viper() {
	viper.Set("fido2.storage", "")
	viper.Set("fido2.storage_path", "")
}

// captureRPPolicyStdout redirects os.Stdout to a pipe for the duration of fn(),
// returning the captured output as a string.
func captureRPPolicyStdout(t *testing.T, fn func()) string {
	t.Helper()

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	os.Stdout = w

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close pipe writer: %v", err)
	}
	os.Stdout = origStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read pipe: %v", err)
	}

	return buf.String()
}

// newRPPolicyTestDir creates a temporary directory for file-backed RP policy
// storage and registers cleanup with testing.T.
func newRPPolicyTestDir(t *testing.T, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// --- RPPolicyCmd structure tests ---

func TestRPPolicyCmd_Help(t *testing.T) {
	resetFIDO2PolicyFlags()

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"fido2", "policy", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("fido2 policy --help failed: %v", err)
	}

	output := buf.String()
	for _, keyword := range []string{"policy", "list", "set", "get", "delete", "rpid"} {
		if !strings.Contains(strings.ToLower(output), keyword) {
			t.Errorf("fido2 policy help output missing %q", keyword)
		}
	}
}

func TestRPPolicyCmd_SubcommandRegistration(t *testing.T) {
	expected := map[string]bool{
		"list":   false,
		"set":    false,
		"get":    false,
		"delete": false,
	}

	for _, cmd := range rpPolicyCmd.Commands() {
		if _, ok := expected[cmd.Name()]; ok {
			expected[cmd.Name()] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("fido2 policy subcommand %q not registered", name)
		}
	}
}

func TestRPPolicyCmd_SubcommandRegistrationMissing(t *testing.T) {
	for _, cmd := range rpPolicyCmd.Commands() {
		if cmd.Name() == "nonexistent" {
			t.Error("unexpected subcommand 'nonexistent' found")
		}
	}
}

// --- Error type tests ---

func TestRPPolicyErrors(t *testing.T) {
	errs := []struct {
		err    error
		prefix string
	}{
		{ErrRPPolicyRPIDRequired, "fido2 policy:"},
		{ErrRPPolicyStoreCreationFailed, "fido2 policy:"},
		{ErrRPPolicyListFailed, "fido2 policy:"},
		{ErrRPPolicyGetFailed, "fido2 policy:"},
		{ErrRPPolicySetFailed, "fido2 policy:"},
		{ErrRPPolicyDeleteFailed, "fido2 policy:"},
		{ErrRPPolicyMarshalFailed, "fido2 policy:"},
		{ErrRPPolicyInvalidUPOverride, "fido2 policy:"},
		{ErrFIDO2ProfileInvalidTransport, "fido2 profile:"},
	}

	for _, tc := range errs {
		if tc.err.Error() == "" {
			t.Errorf("RP policy error has empty message: %v", tc.err)
		}
		if !strings.HasPrefix(tc.err.Error(), tc.prefix) {
			t.Errorf("RP policy error missing %q prefix: %v", tc.prefix, tc.err)
		}
	}
}

func TestRPPolicyErrors_AreDistinct(t *testing.T) {
	if errors.Is(ErrRPPolicyRPIDRequired, ErrRPPolicySetFailed) {
		t.Error("ErrRPPolicyRPIDRequired and ErrRPPolicySetFailed should be distinct")
	}
	if errors.Is(ErrRPPolicyGetFailed, ErrRPPolicyDeleteFailed) {
		t.Error("ErrRPPolicyGetFailed and ErrRPPolicyDeleteFailed should be distinct")
	}
	if errors.Is(ErrRPPolicyInvalidUPOverride, ErrRPPolicyRPIDRequired) {
		t.Error("ErrRPPolicyInvalidUPOverride and ErrRPPolicyRPIDRequired should be distinct")
	}
	if errors.Is(ErrFIDO2ProfileInvalidTransport, ErrRPPolicyRPIDRequired) {
		t.Error("ErrFIDO2ProfileInvalidTransport and ErrRPPolicyRPIDRequired should be distinct")
	}
}

// --- List subcommand tests ---

func TestRPPolicyList_Empty(t *testing.T) {
	resetFIDO2PolicyFlags()
	setFIDO2ViperMemory()
	defer resetFIDO2Viper()

	output := captureRPPolicyStdout(t, func() {
		RootCmd.SetArgs([]string{"fido2", "policy", "list"})
		err := RootCmd.Execute()
		if err != nil {
			t.Fatalf("fido2 policy list failed: %v", err)
		}
	})

	if !strings.Contains(output, "No RP policies configured.") {
		t.Errorf("expected 'No RP policies configured.' in output, got: %q", output)
	}
}

func TestRPPolicyList_WithPolicies(t *testing.T) {
	resetFIDO2PolicyFlags()
	storePath := newRPPolicyTestDir(t, "rp-policy-list-*")
	setFIDO2ViperFile(storePath)
	defer resetFIDO2Viper()

	// Pre-populate policies using the store directly.
	store, err := createFIDO2RPPolicyStore(buildFIDO2Config())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	if err := store.SetPolicy(&authenticator.RPPolicy{
		RPID:       "example.com",
		UVOverride: "required",
	}); err != nil {
		t.Fatalf("failed to set policy: %v", err)
	}
	if err := store.SetPolicy(&authenticator.RPPolicy{
		RPID:    "blocked.com",
		Blocked: true,
	}); err != nil {
		t.Fatalf("failed to set policy: %v", err)
	}

	output := captureRPPolicyStdout(t, func() {
		resetFIDO2PolicyFlags()
		setFIDO2ViperFile(storePath)
		RootCmd.SetArgs([]string{"fido2", "policy", "list"})
		if execErr := RootCmd.Execute(); execErr != nil {
			t.Fatalf("fido2 policy list failed: %v", execErr)
		}
	})

	if !strings.Contains(output, "example.com") {
		t.Error("policy list output missing 'example.com'")
	}
	if !strings.Contains(output, "blocked.com") {
		t.Error("policy list output missing 'blocked.com'")
	}
	if !strings.Contains(output, "RPID") {
		t.Error("policy list output missing table header 'RPID'")
	}
}

// --- Set subcommand tests ---

func TestRPPolicySet_Success(t *testing.T) {
	resetFIDO2PolicyFlags()
	storePath := newRPPolicyTestDir(t, "rp-policy-set-*")
	setFIDO2ViperFile(storePath)
	defer resetFIDO2Viper()

	output := captureRPPolicyStdout(t, func() {
		RootCmd.SetArgs([]string{
			"fido2", "policy", "set",
			"--rpid", "example.com",
			"--uv", "required",
		})
		if execErr := RootCmd.Execute(); execErr != nil {
			t.Fatalf("fido2 policy set failed: %v", execErr)
		}
	})

	if !strings.Contains(output, "Policy set for RP: example.com") {
		t.Errorf("unexpected output: %q", output)
	}

	// Verify the policy was persisted by reading from the store.
	store, err := createFIDO2RPPolicyStore(buildFIDO2Config())
	if err != nil {
		t.Fatalf("failed to create store for verification: %v", err)
	}
	policy, err := store.GetPolicy("example.com")
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if policy.UVOverride != "required" {
		t.Errorf("UVOverride = %q, want %q", policy.UVOverride, "required")
	}
}

func TestRPPolicySet_MissingRPID(t *testing.T) {
	resetFIDO2PolicyFlags()
	setFIDO2ViperMemory()
	defer resetFIDO2Viper()

	RootCmd.SetArgs([]string{"fido2", "policy", "set", "--uv", "required"})
	err := RootCmd.Execute()
	if !errors.Is(err, ErrRPPolicyRPIDRequired) {
		t.Errorf("error = %v, want %v", err, ErrRPPolicyRPIDRequired)
	}
}

func TestRPPolicySet_InvalidUV(t *testing.T) {
	resetFIDO2PolicyFlags()
	setFIDO2ViperMemory()
	defer resetFIDO2Viper()

	RootCmd.SetArgs([]string{
		"fido2", "policy", "set",
		"--rpid", "example.com",
		"--uv", "invalid-uv-value",
	})
	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid --uv value")
	}
	// The RPPolicy.Validate() returns ErrInvalidParameter for invalid UV.
	if !errors.Is(err, authenticator.ErrInvalidParameter) {
		t.Errorf("error = %v, want %v", err, authenticator.ErrInvalidParameter)
	}
}

func TestRPPolicySet_InvalidUP(t *testing.T) {
	resetFIDO2PolicyFlags()
	setFIDO2ViperMemory()
	defer resetFIDO2Viper()

	RootCmd.SetArgs([]string{
		"fido2", "policy", "set",
		"--rpid", "example.com",
		"--up", "invalid",
	})
	err := RootCmd.Execute()
	if !errors.Is(err, ErrRPPolicyInvalidUPOverride) {
		t.Errorf("error = %v, want %v", err, ErrRPPolicyInvalidUPOverride)
	}
}

func TestRPPolicySet_ValidUPTrue(t *testing.T) {
	resetFIDO2PolicyFlags()
	storePath := newRPPolicyTestDir(t, "rp-policy-set-up-true-*")
	setFIDO2ViperFile(storePath)
	defer resetFIDO2Viper()

	output := captureRPPolicyStdout(t, func() {
		RootCmd.SetArgs([]string{
			"fido2", "policy", "set",
			"--rpid", "example.com",
			"--up", "true",
		})
		if execErr := RootCmd.Execute(); execErr != nil {
			t.Fatalf("fido2 policy set failed: %v", execErr)
		}
	})

	if !strings.Contains(output, "Policy set for RP: example.com") {
		t.Errorf("unexpected output: %q", output)
	}

	// Verify UP override was set.
	store, err := createFIDO2RPPolicyStore(buildFIDO2Config())
	if err != nil {
		t.Fatalf("failed to create store for verification: %v", err)
	}
	policy, err := store.GetPolicy("example.com")
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if policy.UPOverride == nil {
		t.Fatal("UPOverride should not be nil")
	}
	if !*policy.UPOverride {
		t.Error("UPOverride should be true")
	}
}

func TestRPPolicySet_ValidUPFalse(t *testing.T) {
	resetFIDO2PolicyFlags()
	storePath := newRPPolicyTestDir(t, "rp-policy-set-up-false-*")
	setFIDO2ViperFile(storePath)
	defer resetFIDO2Viper()

	output := captureRPPolicyStdout(t, func() {
		RootCmd.SetArgs([]string{
			"fido2", "policy", "set",
			"--rpid", "example.com",
			"--up", "false",
		})
		if execErr := RootCmd.Execute(); execErr != nil {
			t.Fatalf("fido2 policy set failed: %v", execErr)
		}
	})

	if !strings.Contains(output, "Policy set for RP: example.com") {
		t.Errorf("unexpected output: %q", output)
	}

	store, err := createFIDO2RPPolicyStore(buildFIDO2Config())
	if err != nil {
		t.Fatalf("failed to create store for verification: %v", err)
	}
	policy, err := store.GetPolicy("example.com")
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if policy.UPOverride == nil {
		t.Fatal("UPOverride should not be nil")
	}
	if *policy.UPOverride {
		t.Error("UPOverride should be false")
	}
}

func TestRPPolicySet_BlockedRP(t *testing.T) {
	resetFIDO2PolicyFlags()
	storePath := newRPPolicyTestDir(t, "rp-policy-set-blocked-*")
	setFIDO2ViperFile(storePath)
	defer resetFIDO2Viper()

	output := captureRPPolicyStdout(t, func() {
		RootCmd.SetArgs([]string{
			"fido2", "policy", "set",
			"--rpid", "malicious.com",
			"--blocked",
		})
		if execErr := RootCmd.Execute(); execErr != nil {
			t.Fatalf("fido2 policy set failed: %v", execErr)
		}
	})

	if !strings.Contains(output, "Policy set for RP: malicious.com") {
		t.Errorf("unexpected output: %q", output)
	}

	store, err := createFIDO2RPPolicyStore(buildFIDO2Config())
	if err != nil {
		t.Fatalf("failed to create store for verification: %v", err)
	}
	policy, err := store.GetPolicy("malicious.com")
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if !policy.Blocked {
		t.Error("policy should be blocked")
	}
}

// --- Get subcommand tests ---

func TestRPPolicyGet_Success(t *testing.T) {
	resetFIDO2PolicyFlags()
	storePath := newRPPolicyTestDir(t, "rp-policy-get-*")
	setFIDO2ViperFile(storePath)
	defer resetFIDO2Viper()

	// Pre-populate a policy.
	store, err := createFIDO2RPPolicyStore(buildFIDO2Config())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	if err := store.SetPolicy(&authenticator.RPPolicy{
		RPID:       "example.com",
		UVOverride: "required",
		Enterprise: true,
	}); err != nil {
		t.Fatalf("failed to set policy: %v", err)
	}

	output := captureRPPolicyStdout(t, func() {
		resetFIDO2PolicyFlags()
		setFIDO2ViperFile(storePath)
		RootCmd.SetArgs([]string{"fido2", "policy", "get", "--rpid", "example.com"})
		if execErr := RootCmd.Execute(); execErr != nil {
			t.Fatalf("fido2 policy get failed: %v", execErr)
		}
	})

	// Output should be valid JSON.
	var policy authenticator.RPPolicy
	if err := json.Unmarshal([]byte(output), &policy); err != nil {
		t.Fatalf("failed to parse JSON output: %v (output: %q)", err, output)
	}

	if policy.RPID != "example.com" {
		t.Errorf("RPID = %q, want %q", policy.RPID, "example.com")
	}
	if policy.UVOverride != "required" {
		t.Errorf("UVOverride = %q, want %q", policy.UVOverride, "required")
	}
	if !policy.Enterprise {
		t.Error("Enterprise should be true")
	}
}

func TestRPPolicyGet_MissingRPID(t *testing.T) {
	resetFIDO2PolicyFlags()
	setFIDO2ViperMemory()
	defer resetFIDO2Viper()

	RootCmd.SetArgs([]string{"fido2", "policy", "get"})
	err := RootCmd.Execute()
	if !errors.Is(err, ErrRPPolicyRPIDRequired) {
		t.Errorf("error = %v, want %v", err, ErrRPPolicyRPIDRequired)
	}
}

func TestRPPolicyGet_NotFound(t *testing.T) {
	resetFIDO2PolicyFlags()
	setFIDO2ViperMemory()
	defer resetFIDO2Viper()

	RootCmd.SetArgs([]string{"fido2", "policy", "get", "--rpid", "nonexistent.com"})
	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent RP policy")
	}
	if !errors.Is(err, ErrRPPolicyGetFailed) {
		t.Errorf("error = %v, want wrapped %v", err, ErrRPPolicyGetFailed)
	}
}

// --- Delete subcommand tests ---

func TestRPPolicyDelete_Success(t *testing.T) {
	resetFIDO2PolicyFlags()
	storePath := newRPPolicyTestDir(t, "rp-policy-delete-*")
	setFIDO2ViperFile(storePath)
	defer resetFIDO2Viper()

	// Pre-populate a policy.
	store, err := createFIDO2RPPolicyStore(buildFIDO2Config())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	if err := store.SetPolicy(&authenticator.RPPolicy{
		RPID:       "delete-me.com",
		UVOverride: "discouraged",
	}); err != nil {
		t.Fatalf("failed to set policy: %v", err)
	}

	output := captureRPPolicyStdout(t, func() {
		resetFIDO2PolicyFlags()
		setFIDO2ViperFile(storePath)
		RootCmd.SetArgs([]string{"fido2", "policy", "delete", "--rpid", "delete-me.com"})
		if execErr := RootCmd.Execute(); execErr != nil {
			t.Fatalf("fido2 policy delete failed: %v", execErr)
		}
	})

	if !strings.Contains(output, "Policy deleted for RP: delete-me.com") {
		t.Errorf("unexpected output: %q", output)
	}

	// Verify the policy was deleted.
	store2, err := createFIDO2RPPolicyStore(buildFIDO2Config())
	if err != nil {
		t.Fatalf("failed to create store for verification: %v", err)
	}
	_, err = store2.GetPolicy("delete-me.com")
	if !errors.Is(err, authenticator.ErrRPPolicyNotFound) {
		t.Errorf("expected ErrRPPolicyNotFound after delete, got: %v", err)
	}
}

func TestRPPolicyDelete_MissingRPID(t *testing.T) {
	resetFIDO2PolicyFlags()
	setFIDO2ViperMemory()
	defer resetFIDO2Viper()

	RootCmd.SetArgs([]string{"fido2", "policy", "delete"})
	err := RootCmd.Execute()
	if !errors.Is(err, ErrRPPolicyRPIDRequired) {
		t.Errorf("error = %v, want %v", err, ErrRPPolicyRPIDRequired)
	}
}

func TestRPPolicyDelete_NotFound(t *testing.T) {
	resetFIDO2PolicyFlags()
	setFIDO2ViperMemory()
	defer resetFIDO2Viper()

	RootCmd.SetArgs([]string{"fido2", "policy", "delete", "--rpid", "nonexistent.com"})
	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for deleting nonexistent RP policy")
	}
	if !errors.Is(err, ErrRPPolicyDeleteFailed) {
		t.Errorf("error = %v, want wrapped %v", err, ErrRPPolicyDeleteFailed)
	}
}

// --- Profile subcommand tests ---

// newFIDO2ProfileTestDir points the FIDO2 storage path at an isolated
// temporary directory so profile persistence tests never touch the
// repository-relative default store, and restores the previous viper state.
func newFIDO2ProfileTestDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	previous := viper.GetString("fido2.storage_path")
	viper.Set("fido2.storage_path", dir)
	t.Cleanup(func() { viper.Set("fido2.storage_path", previous) })
	return dir
}

// runFIDO2ProfileCommand executes a fido2 profile subcommand through the root
// command, returning what the command wrote to its output stream. The stream
// is bound explicitly rather than by redirecting os.Stdout so the result does
// not depend on output plumbing left behind by other tests in the package.
func runFIDO2ProfileCommand(t *testing.T, args ...string) string {
	t.Helper()

	resetFIDO2PolicyFlags()

	var buf bytes.Buffer
	RootCmd.SetOut(&buf)
	RootCmd.SetErr(&buf)
	t.Cleanup(func() {
		RootCmd.SetOut(os.Stdout)
		RootCmd.SetErr(os.Stderr)
	})

	RootCmd.SetArgs(args)
	if execErr := RootCmd.Execute(); execErr != nil {
		t.Fatalf("%v failed: %v", args, execErr)
	}
	return buf.String()
}

// TestFIDO2ProfileSet_PersistsTransports verifies the transports override is
// written to the profile store and read back, not merely printed.
func TestFIDO2ProfileSet_PersistsTransports(t *testing.T) {
	cfgDir := newFIDO2ProfileTestDir(t)

	output := runFIDO2ProfileCommand(t, "fido2", "profile", "set", "--transports", "usb,internal")

	if !strings.Contains(output, "usb, internal") {
		t.Errorf("profile set output missing transports, got: %s", output)
	}
	if !strings.Contains(output, "Profile saved to") {
		t.Errorf("profile set output missing save confirmation, got: %s", output)
	}

	stored, err := loadFIDO2Profile(context.Background(), buildFIDO2Config())
	if err != nil {
		t.Fatalf("loadFIDO2Profile: %v", err)
	}
	if len(stored.Transports) != 2 || stored.Transports[0] != "usb" || stored.Transports[1] != "internal" {
		t.Errorf("persisted transports = %v, want [usb internal]", stored.Transports)
	}

	// The document really landed on disk under the configured storage path.
	profilePath, pathErr := fido2ProfileStorePath(buildFIDO2Config())
	if pathErr != nil {
		t.Fatalf("fido2ProfileStorePath: %v", pathErr)
	}
	if _, statErr := os.Stat(profilePath); statErr != nil {
		t.Errorf("profile store directory missing under %s: %v", cfgDir, statErr)
	}

	// "profile show" reports the same persisted values.
	showOutput := runFIDO2ProfileCommand(t, "fido2", "profile", "show")
	if !strings.Contains(showOutput, "usb, internal") {
		t.Errorf("profile show output missing persisted transports, got: %s", showOutput)
	}
}

// TestFIDO2ProfileSet_AllTransports verifies every accepted transport value
// round-trips through the store.
func TestFIDO2ProfileSet_AllTransports(t *testing.T) {
	newFIDO2ProfileTestDir(t)

	runFIDO2ProfileCommand(t, "fido2", "profile", "set", "--transports", "usb,nfc,ble,internal,hybrid")

	stored, err := loadFIDO2Profile(context.Background(), buildFIDO2Config())
	if err != nil {
		t.Fatalf("loadFIDO2Profile: %v", err)
	}
	want := []string{"usb", "nfc", "ble", "internal", "hybrid"}
	if len(stored.Transports) != len(want) {
		t.Fatalf("persisted transports = %v, want %v", stored.Transports, want)
	}
	for i, transport := range want {
		if stored.Transports[i] != transport {
			t.Errorf("transport[%d] = %q, want %q", i, stored.Transports[i], transport)
		}
	}
}

// TestFIDO2ProfileSet_EnterpriseAttestation verifies the enterprise
// attestation flag is persisted.
func TestFIDO2ProfileSet_EnterpriseAttestation(t *testing.T) {
	newFIDO2ProfileTestDir(t)

	output := runFIDO2ProfileCommand(t, "fido2", "profile", "set", "--enterprise-attestation")

	if !strings.Contains(output, "Enterprise Attestation") {
		t.Error("profile set output missing 'Enterprise Attestation'")
	}

	stored, err := loadFIDO2Profile(context.Background(), buildFIDO2Config())
	if err != nil {
		t.Fatalf("loadFIDO2Profile: %v", err)
	}
	if !stored.EnterpriseAttestation {
		t.Error("enterprise attestation was not persisted")
	}
}

// TestFIDO2ProfileSet_PartialUpdatePreservesStoredSettings verifies a second
// "set" that names only one setting leaves the other stored value intact.
func TestFIDO2ProfileSet_PartialUpdatePreservesStoredSettings(t *testing.T) {
	newFIDO2ProfileTestDir(t)

	runFIDO2ProfileCommand(t, "fido2", "profile", "set", "--transports", "nfc")
	runFIDO2ProfileCommand(t, "fido2", "profile", "set", "--enterprise-attestation")

	stored, err := loadFIDO2Profile(context.Background(), buildFIDO2Config())
	if err != nil {
		t.Fatalf("loadFIDO2Profile: %v", err)
	}
	if !stored.EnterpriseAttestation {
		t.Error("enterprise attestation was not persisted")
	}
	if len(stored.Transports) != 1 || stored.Transports[0] != "nfc" {
		t.Errorf("transports = %v, want [nfc] preserved across the partial update", stored.Transports)
	}
}

// TestFIDO2ProfileSet_ClearsTransports verifies an explicit empty value
// removes the override and restores the authenticator default.
func TestFIDO2ProfileSet_ClearsTransports(t *testing.T) {
	newFIDO2ProfileTestDir(t)

	runFIDO2ProfileCommand(t, "fido2", "profile", "set", "--transports", "ble")
	output := runFIDO2ProfileCommand(t, "fido2", "profile", "set", "--transports", "")

	if !strings.Contains(output, "(default: usb)") {
		t.Errorf("cleared profile should report the authenticator default, got: %s", output)
	}

	stored, err := loadFIDO2Profile(context.Background(), buildFIDO2Config())
	if err != nil {
		t.Fatalf("loadFIDO2Profile: %v", err)
	}
	if len(stored.Transports) != 0 {
		t.Errorf("transports = %v, want empty after clearing", stored.Transports)
	}
}

// TestFIDO2ProfileSet_NoSettings verifies the command fails closed rather
// than writing an empty profile when no setting is named.
func TestFIDO2ProfileSet_NoSettings(t *testing.T) {
	newFIDO2ProfileTestDir(t)
	resetFIDO2PolicyFlags()

	RootCmd.SetArgs([]string{"fido2", "profile", "set"})
	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected an error when no profile setting is supplied")
	}
	if !errors.Is(err, ErrFIDO2ProfileNoSettings) {
		t.Errorf("error = %v, want %v", err, ErrFIDO2ProfileNoSettings)
	}

	stored, loadErr := loadFIDO2Profile(context.Background(), buildFIDO2Config())
	if loadErr != nil {
		t.Fatalf("loadFIDO2Profile: %v", loadErr)
	}
	if len(stored.Transports) != 0 || stored.EnterpriseAttestation {
		t.Errorf("no profile should have been written, got %+v", stored)
	}
}

func TestFIDO2ProfileSet_InvalidTransport(t *testing.T) {
	newFIDO2ProfileTestDir(t)
	resetFIDO2PolicyFlags()

	RootCmd.SetArgs([]string{
		"fido2", "profile", "set",
		"--transports", "usb,carrier-pigeon",
	})
	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid transport")
	}
	if !errors.Is(err, ErrFIDO2ProfileInvalidTransport) {
		t.Errorf("error = %v, want %v", err, ErrFIDO2ProfileInvalidTransport)
	}
	if !strings.Contains(err.Error(), "carrier-pigeon") {
		t.Errorf("error should mention the invalid transport, got: %v", err)
	}

	stored, loadErr := loadFIDO2Profile(context.Background(), buildFIDO2Config())
	if loadErr != nil {
		t.Fatalf("loadFIDO2Profile: %v", loadErr)
	}
	if len(stored.Transports) != 0 {
		t.Errorf("a rejected transports list must not be persisted, got %v", stored.Transports)
	}
}

// TestFIDO2ProfileShow_Default verifies "profile show" reports the
// authenticator defaults against a store that was never written.
func TestFIDO2ProfileShow_Default(t *testing.T) {
	newFIDO2ProfileTestDir(t)

	output := runFIDO2ProfileCommand(t, "fido2", "profile", "show")

	if !strings.Contains(output, "(default: usb)") {
		t.Errorf("show output missing the transports default, got: %s", output)
	}
	if !strings.Contains(output, "Enterprise Attestation") {
		t.Errorf("show output missing 'Enterprise Attestation', got: %s", output)
	}
	if !strings.Contains(output, "Profile store:") {
		t.Errorf("show output missing the store path, got: %s", output)
	}
}

// TestLoadFIDO2Profile_CorruptDocument verifies a corrupt stored profile is
// reported rather than silently treated as the default.
func TestLoadFIDO2Profile_CorruptDocument(t *testing.T) {
	newFIDO2ProfileTestDir(t)
	cfg := buildFIDO2Config()

	backend, err := openFIDO2ProfileStore(cfg)
	if err != nil {
		t.Fatalf("openFIDO2ProfileStore: %v", err)
	}
	if putErr := backend.Put(context.Background(), fido2ProfileKey, []byte("{not json")); putErr != nil {
		t.Fatalf("Put: %v", putErr)
	}
	if closeErr := backend.Close(); closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}

	if _, err := loadFIDO2Profile(context.Background(), cfg); !errors.Is(err, ErrFIDO2ProfileDecodeFailed) {
		t.Errorf("error = %v, want %v", err, ErrFIDO2ProfileDecodeFailed)
	}
}

// TestSaveFIDO2Profile_InvalidTransport verifies the store layer validates
// the profile before writing anything.
func TestSaveFIDO2Profile_InvalidTransport(t *testing.T) {
	newFIDO2ProfileTestDir(t)
	cfg := buildFIDO2Config()

	err := saveFIDO2Profile(context.Background(), cfg, &FIDO2Profile{Transports: []string{"telepathy"}})
	if !errors.Is(err, ErrFIDO2ProfileInvalidTransport) {
		t.Errorf("error = %v, want %v", err, ErrFIDO2ProfileInvalidTransport)
	}

	stored, loadErr := loadFIDO2Profile(context.Background(), cfg)
	if loadErr != nil {
		t.Fatalf("loadFIDO2Profile: %v", loadErr)
	}
	if len(stored.Transports) != 0 {
		t.Errorf("invalid profile must not be written, got %v", stored.Transports)
	}
}

// TestOpenFIDO2ProfileStore_UnusableStoragePath verifies the store fails
// closed when the configured storage path cannot hold a directory.
func TestOpenFIDO2ProfileStore_UnusableStoragePath(t *testing.T) {
	dir := newFIDO2ProfileTestDir(t)

	// A regular file where the store directory must go.
	blocker := filepath.Join(dir, fido2ProfileStoreSubdir)
	if err := os.WriteFile(blocker, []byte("not a directory"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := openFIDO2ProfileStore(buildFIDO2Config()); !errors.Is(err, ErrFIDO2ProfileStoreOpenFailed) {
		t.Errorf("error = %v, want %v", err, ErrFIDO2ProfileStoreOpenFailed)
	}
}

// TestFIDO2ProfileStorePath_DefaultsWhenUnset verifies the store resolves
// through the shared xkey data-directory chain (resolveFIDO2StoragePath,
// datadir.go) when cfg.StoragePath is unset, landing under the resolved
// xkey home rather than a cwd-relative default (go-xkms#929).
func TestFIDO2ProfileStorePath_DefaultsWhenUnset(t *testing.T) {
	root := t.TempDir()
	xhome.SetRoot(root)
	t.Cleanup(xhome.ResetRoot)

	previousViper := viper.GetString("data_dir")
	viper.Set("data_dir", "")
	t.Cleanup(func() { viper.Set("data_dir", previousViper) })

	path, err := fido2ProfileStorePath(&FIDO2Config{})
	if err != nil {
		t.Fatalf("fido2ProfileStorePath: %v", err)
	}
	want := filepath.Join(root, "data", "fido2", fido2ProfileStoreSubdir)
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if !filepath.IsAbs(path) {
		t.Errorf("path = %q, want an absolute path", path)
	}
}

// TestFIDO2ProfileStorePath_ErrorWhenHomeUnresolvable verifies the error
// path: when the shared data-directory chain cannot resolve an xkey home
// (go-xkms#929), fido2ProfileStorePath fails closed with a typed error
// instead of falling back to a cwd-relative path.
func TestFIDO2ProfileStorePath_ErrorWhenHomeUnresolvable(t *testing.T) {
	xhome.ResetRoot()
	t.Cleanup(xhome.ResetRoot)

	previousViper := viper.GetString("data_dir")
	viper.Set("data_dir", "")
	t.Cleanup(func() { viper.Set("data_dir", previousViper) })

	// A regular file, not a directory: XKEY_HOME can neither be used nor
	// created as a directory, so resolution must fail rather than silently
	// falling through to a cwd-relative default.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("XKEY_HOME", blocker)

	if _, err := fido2ProfileStorePath(&FIDO2Config{}); err == nil {
		t.Error("fido2ProfileStorePath should fail when the xkey home cannot be resolved")
	}
}

// --- Valid transports map tests ---

func TestFIDO2ValidTransports(t *testing.T) {
	expected := []string{"usb", "nfc", "ble", "internal", "hybrid"}
	for _, transport := range expected {
		if !fido2ValidTransports[transport] {
			t.Errorf("transport %q should be valid", transport)
		}
	}
}

func TestFIDO2ValidTransports_Invalid(t *testing.T) {
	invalid := []string{"wifi", "carrier-pigeon", "USB", "bluetooth", ""}
	for _, transport := range invalid {
		if fido2ValidTransports[transport] {
			t.Errorf("transport %q should be invalid", transport)
		}
	}
}

// --- createFIDO2RPPolicyStore tests ---

func TestCreateFIDO2RPPolicyStore_Memory(t *testing.T) {
	cfg := &FIDO2Config{StorageType: FIDO2StorageTypeMemory}
	store, err := createFIDO2RPPolicyStore(cfg)
	if err != nil {
		t.Fatalf("createFIDO2RPPolicyStore(memory) failed: %v", err)
	}
	if store == nil {
		t.Fatal("store should not be nil")
	}

	// Verify store is functional.
	policies, err := store.ListPolicies()
	if err != nil {
		t.Fatalf("ListPolicies failed: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(policies))
	}
}

func TestCreateFIDO2RPPolicyStore_File(t *testing.T) {
	storePath := newRPPolicyTestDir(t, "rp-policy-store-file-*")
	cfg := &FIDO2Config{
		StorageType: FIDO2StorageTypeFile,
		StoragePath: storePath,
	}
	store, err := createFIDO2RPPolicyStore(cfg)
	if err != nil {
		t.Fatalf("createFIDO2RPPolicyStore(file) failed: %v", err)
	}
	if store == nil {
		t.Fatal("store should not be nil")
	}

	// Verify store is functional with set+get round-trip.
	policy := &authenticator.RPPolicy{RPID: "test.com"}
	if err := store.SetPolicy(policy); err != nil {
		t.Fatalf("SetPolicy failed: %v", err)
	}
	got, err := store.GetPolicy("test.com")
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if got.RPID != "test.com" {
		t.Errorf("RPID = %q, want %q", got.RPID, "test.com")
	}
}

func TestCreateFIDO2RPPolicyStore_InvalidType(t *testing.T) {
	cfg := &FIDO2Config{StorageType: "invalid"}
	_, err := createFIDO2RPPolicyStore(cfg)
	if !errors.Is(err, ErrFIDO2InvalidStorageType) {
		t.Errorf("error = %v, want %v", err, ErrFIDO2InvalidStorageType)
	}
}

// --- Attestation override tests ---

func TestRPPolicySet_ValidAttestationOverride(t *testing.T) {
	resetFIDO2PolicyFlags()
	storePath := newRPPolicyTestDir(t, "rp-policy-attest-*")
	setFIDO2ViperFile(storePath)
	defer resetFIDO2Viper()

	output := captureRPPolicyStdout(t, func() {
		RootCmd.SetArgs([]string{
			"fido2", "policy", "set",
			"--rpid", "enterprise.com",
			"--attestation", "enterprise",
			"--enterprise",
		})
		if execErr := RootCmd.Execute(); execErr != nil {
			t.Fatalf("fido2 policy set failed: %v", execErr)
		}
	})

	if !strings.Contains(output, "Policy set for RP: enterprise.com") {
		t.Errorf("unexpected output: %q", output)
	}

	store, err := createFIDO2RPPolicyStore(buildFIDO2Config())
	if err != nil {
		t.Fatalf("failed to create store for verification: %v", err)
	}
	policy, err := store.GetPolicy("enterprise.com")
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if policy.AttestationOverride != "enterprise" {
		t.Errorf("AttestationOverride = %q, want %q", policy.AttestationOverride, "enterprise")
	}
	if !policy.Enterprise {
		t.Error("Enterprise should be true")
	}
}

func TestRPPolicySet_InvalidAttestationOverride(t *testing.T) {
	resetFIDO2PolicyFlags()
	setFIDO2ViperMemory()
	defer resetFIDO2Viper()

	RootCmd.SetArgs([]string{
		"fido2", "policy", "set",
		"--rpid", "example.com",
		"--attestation", "invalid-attestation",
	})
	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid attestation override")
	}
	// The RPPolicy.Validate() returns ErrInvalidParameter for invalid attestation.
	if !errors.Is(err, authenticator.ErrInvalidParameter) {
		t.Errorf("error = %v, want %v", err, authenticator.ErrInvalidParameter)
	}
}
