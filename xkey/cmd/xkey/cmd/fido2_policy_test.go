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
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
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

func TestFIDO2ProfileSet_ValidTransports(t *testing.T) {
	resetFIDO2PolicyFlags()

	output := captureRPPolicyStdout(t, func() {
		RootCmd.SetArgs([]string{
			"fido2", "profile", "set",
			"--transports", "usb,internal",
		})
		if execErr := RootCmd.Execute(); execErr != nil {
			t.Fatalf("fido2 profile set failed: %v", execErr)
		}
	})

	if !strings.Contains(output, "usb") {
		t.Error("profile set output missing 'usb'")
	}
	if !strings.Contains(output, "internal") {
		t.Error("profile set output missing 'internal'")
	}
	if !strings.Contains(output, "Transports") {
		t.Error("profile set output missing 'Transports' header")
	}
}

func TestFIDO2ProfileSet_InvalidTransport(t *testing.T) {
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
}

func TestFIDO2ProfileSet_AllTransports(t *testing.T) {
	resetFIDO2PolicyFlags()

	output := captureRPPolicyStdout(t, func() {
		RootCmd.SetArgs([]string{
			"fido2", "profile", "set",
			"--transports", "usb,nfc,ble,internal,hybrid",
		})
		if execErr := RootCmd.Execute(); execErr != nil {
			t.Fatalf("fido2 profile set failed: %v", execErr)
		}
	})

	for _, transport := range []string{"usb", "nfc", "ble", "internal", "hybrid"} {
		if !strings.Contains(output, transport) {
			t.Errorf("profile set output missing transport %q", transport)
		}
	}
}

func TestFIDO2ProfileSet_EnterpriseAttestation(t *testing.T) {
	resetFIDO2PolicyFlags()

	output := captureRPPolicyStdout(t, func() {
		RootCmd.SetArgs([]string{
			"fido2", "profile", "set",
			"--enterprise-attestation",
		})
		if execErr := RootCmd.Execute(); execErr != nil {
			t.Fatalf("fido2 profile set failed: %v", execErr)
		}
	})

	if !strings.Contains(output, "Enterprise Attestation") {
		t.Error("profile set output missing 'Enterprise Attestation'")
	}
	if !strings.Contains(output, "true") {
		t.Error("profile set output missing 'true' for enterprise attestation")
	}
}

func TestFIDO2ProfileSet_EmptyTransports(t *testing.T) {
	resetFIDO2PolicyFlags()

	output := captureRPPolicyStdout(t, func() {
		RootCmd.SetArgs([]string{
			"fido2", "profile", "set",
		})
		if execErr := RootCmd.Execute(); execErr != nil {
			t.Fatalf("fido2 profile set failed: %v", execErr)
		}
	})

	// With no transports, the output should not contain a Transports row
	// but should still show the Enterprise Attestation row.
	if !strings.Contains(output, "Enterprise Attestation") {
		t.Error("profile set output missing 'Enterprise Attestation'")
	}
	if !strings.Contains(output, "Profile settings displayed") {
		t.Error("profile set output missing trailing message")
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
