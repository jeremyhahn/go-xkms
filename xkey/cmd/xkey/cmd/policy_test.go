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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/spf13/pflag"

	pcrpolicy "github.com/jeremyhahn/go-xkms/xkey/pkg/pcr_policy"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// noCloseStore wraps a PolicyStore and makes Close() a no-op so that
// the shared test store is not closed by the command's defer. The real
// cleanup runs via t.Cleanup().
type noCloseStore struct {
	pcrpolicy.PolicyStore
}

// Close is a no-op for the test wrapper.
func (n *noCloseStore) Close() error { return nil }

// resetPolicyFlags resets all policy subcommand flags to their default
// values. Cobra retains flag state across Execute() calls within the
// same process, which causes test pollution when multiple tests modify
// the same flags.
func resetPolicyFlags() {
	cmds := []*pflag.FlagSet{
		PolicyCmd.PersistentFlags(),
		policyCreateCmd.Flags(),
		policyListCmd.Flags(),
		policyGetCmd.Flags(),
		policyDeleteCmd.Flags(),
		policySetAutoUnsealCmd.Flags(),
		policyClearAutoUnsealCmd.Flags(),
		policyRefreshCmd.Flags(),
		policyVerifyCmd.Flags(),
		policyExportCmd.Flags(),
	}
	for _, fs := range cmds {
		fs.VisitAll(func(f *pflag.Flag) {
			f.Changed = false
			_ = f.Value.Set(f.DefValue)
		})
	}
}

// newTestPolicyStore creates an in-memory PolicyStore for testing and
// installs it as the policyStoreFactory. The previous factory is restored
// on cleanup. The factory returns a no-close wrapper so that the
// command's defer store.Close() does not close the shared test store.
func newTestPolicyStore(t *testing.T) pcrpolicy.PolicyStore {
	t.Helper()

	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	if err != nil {
		t.Fatalf("failed to create kvstore adapter: %v", err)
	}

	store, err := pcrpolicy.NewDAOStore(kvStore)
	if err != nil {
		t.Fatalf("failed to create DAOStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	// Replace the global factory with one that always returns a
	// no-close wrapper around the shared store.
	origFactory := policyStoreFactory
	policyStoreFactory = func(path string) (pcrpolicy.PolicyStore, error) {
		return &noCloseStore{PolicyStore: store}, nil
	}
	t.Cleanup(func() { policyStoreFactory = origFactory })

	return store
}

// seedPolicy creates a policy in the store for testing.
func seedPolicy(t *testing.T, store pcrpolicy.PolicyStore, name string) {
	t.Helper()
	ctx := context.Background()
	pcrs := map[uint][]byte{
		0: {0xAA, 0xBB, 0xCC, 0xDD},
		7: {0xDE, 0xAD, 0xBE, 0xEF},
	}
	_, err := store.Create(ctx, name, "SHA256", pcrs)
	if err != nil {
		t.Fatalf("failed to seed policy %q: %v", name, err)
	}
}

// ---------------------------------------------------------------------------
// PolicyCmd structure tests
// ---------------------------------------------------------------------------

func TestPolicyCmd_Help(t *testing.T) {
	resetPolicyFlags()

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("policy --help failed: %v", err)
	}

	output := buf.String()
	for _, keyword := range []string{
		"policy", "create", "list", "get", "delete",
		"set-auto-unseal", "clear-auto-unseal", "refresh", "verify", "export",
	} {
		if !strings.Contains(strings.ToLower(output), keyword) {
			t.Errorf("policy help output missing %q", keyword)
		}
	}
}

func TestPolicyCmd_HelpContainsExamples(t *testing.T) {
	resetPolicyFlags()

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("policy --help failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "boot-policy") {
		t.Error("policy help output missing example policy name")
	}
}

func TestPolicyCmd_SubcommandRegistration(t *testing.T) {
	expected := map[string]bool{
		"create":            false,
		"list":              false,
		"get":               false,
		"delete":            false,
		"set-auto-unseal":   false,
		"clear-auto-unseal": false,
		"refresh":           false,
		"verify":            false,
		"export":            false,
	}

	for _, cmd := range PolicyCmd.Commands() {
		if _, ok := expected[cmd.Name()]; ok {
			expected[cmd.Name()] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("policy subcommand %q not registered", name)
		}
	}
}

func TestPolicyCmd_SubcommandRegistrationMissing(t *testing.T) {
	for _, cmd := range PolicyCmd.Commands() {
		if cmd.Name() == "nonexistent" {
			t.Error("unexpected subcommand 'nonexistent' found")
		}
	}
}

// ---------------------------------------------------------------------------
// Error type tests
// ---------------------------------------------------------------------------

func TestPolicyErrors(t *testing.T) {
	errs := []error{
		ErrPolicyMissingName,
		ErrPolicyMissingPCRs,
		ErrPolicyInvalidBank,
		ErrPolicyStoreOpenFailed,
		ErrPolicyCreateFailed,
		ErrPolicyListFailed,
		ErrPolicyGetFailed,
		ErrPolicyDeleteFailed,
		ErrPolicyRefreshFailed,
		ErrPolicyVerifyFailed,
		ErrPolicyExportFailed,
		ErrPolicyNotFound,
		ErrPolicyAlreadyExists,
		ErrPolicyReadCurrentFailed,
		ErrPolicyAutoUnsealFailed,
		ErrPolicyClearAutoFailed,
	}

	for _, err := range errs {
		if err.Error() == "" {
			t.Errorf("policy error has empty message: %v", err)
		}
		if !strings.HasPrefix(err.Error(), "policy:") {
			t.Errorf("policy error missing 'policy:' prefix: %v", err)
		}
	}
}

func TestPolicyErrors_AreDistinct(t *testing.T) {
	if errors.Is(ErrPolicyMissingName, ErrPolicyMissingPCRs) {
		t.Error("ErrPolicyMissingName and ErrPolicyMissingPCRs should be distinct")
	}
	if errors.Is(ErrPolicyNotFound, ErrPolicyAlreadyExists) {
		t.Error("ErrPolicyNotFound and ErrPolicyAlreadyExists should be distinct")
	}
	if errors.Is(ErrPolicyAutoUnsealFailed, ErrPolicyClearAutoFailed) {
		t.Error("ErrPolicyAutoUnsealFailed and ErrPolicyClearAutoFailed should be distinct")
	}
}

// ---------------------------------------------------------------------------
// Create subcommand tests
// ---------------------------------------------------------------------------

func TestPolicyCreate_MissingName(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "create", "--pcrs", "0,1,7"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing name argument")
	}
	if !strings.Contains(err.Error(), "accepts 1 arg") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPolicyCreate_MissingPCRs(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "create", "test-policy"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrPolicyMissingPCRs) {
		t.Errorf("error = %v, want %v", err, ErrPolicyMissingPCRs)
	}
}

func TestPolicyCreate_InvalidBank(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{
		"policy", "create", "test-policy",
		"--pcrs", "0,1,7",
		"--bank", "md5",
	})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrPolicyInvalidBank) {
		t.Errorf("error = %v, want %v", err, ErrPolicyInvalidBank)
	}
}

func TestPolicyCreate_InvalidPCRIndex(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{
		"policy", "create", "test-policy",
		"--pcrs", "0,1,99",
	})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for out-of-range PCR index")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// List subcommand tests
// ---------------------------------------------------------------------------

func TestPolicyList_EmptyStore(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "list"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("policy list failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No policies found") {
		t.Errorf("expected 'No policies found' in output, got: %q", output)
	}
}

func TestPolicyList_WithPolicies(t *testing.T) {
	resetPolicyFlags()
	store := newTestPolicyStore(t)

	seedPolicy(t, store, "alpha")
	seedPolicy(t, store, "beta")

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "list"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("policy list failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "alpha") {
		t.Error("policy list output missing 'alpha'")
	}
	if !strings.Contains(output, "beta") {
		t.Error("policy list output missing 'beta'")
	}
	if !strings.Contains(output, "PCR Policies (2)") {
		t.Error("policy list output missing count header")
	}
}

func TestPolicyList_AutoUnsealTag(t *testing.T) {
	resetPolicyFlags()
	store := newTestPolicyStore(t)
	ctx := context.Background()

	seedPolicy(t, store, "auto-policy")
	seedPolicy(t, store, "normal-policy")

	if err := store.SetAutoUnseal(ctx, "auto-policy"); err != nil {
		t.Fatalf("failed to set auto-unseal: %v", err)
	}

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "list"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("policy list failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "[auto-unseal]") {
		t.Error("policy list output missing [auto-unseal] tag")
	}
}

func TestPolicyList_Paginated(t *testing.T) {
	resetPolicyFlags()
	store := newTestPolicyStore(t)

	for _, name := range []string{"aaa", "bbb", "ccc", "ddd", "eee"} {
		seedPolicy(t, store, name)
	}

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "list", "--page", "1", "--page-size", "2"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("policy list paginated failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "5 total") {
		t.Errorf("expected '5 total' in output, got: %q", output)
	}
}

func TestPolicyList_PaginatedEmpty(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "list", "--page", "1", "--page-size", "10"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("policy list paginated empty failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No policies found") {
		t.Errorf("expected 'No policies found' in output, got: %q", output)
	}
}

// ---------------------------------------------------------------------------
// Get subcommand tests
// ---------------------------------------------------------------------------

func TestPolicyGet_Existing(t *testing.T) {
	resetPolicyFlags()
	store := newTestPolicyStore(t)

	seedPolicy(t, store, "boot-policy")

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "get", "boot-policy"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("policy get failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "boot-policy") {
		t.Error("policy get output missing policy name")
	}
	if !strings.Contains(output, "SHA256") {
		t.Error("policy get output missing bank")
	}
	if !strings.Contains(output, "aabbccdd") {
		t.Error("policy get output missing PCR value hex")
	}
}

func TestPolicyGet_AutoUnsealTag(t *testing.T) {
	resetPolicyFlags()
	store := newTestPolicyStore(t)
	ctx := context.Background()

	seedPolicy(t, store, "auto-get")

	if err := store.SetAutoUnseal(ctx, "auto-get"); err != nil {
		t.Fatalf("failed to set auto-unseal: %v", err)
	}

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "get", "auto-get"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("policy get failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "[auto-unseal]") {
		t.Error("policy get output missing [auto-unseal] tag")
	}
}

func TestPolicyGet_NotFound(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "get", "nonexistent"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("error = %v, want %v", err, ErrPolicyNotFound)
	}
}

func TestPolicyGet_MissingName(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "get"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing name argument")
	}
	if !strings.Contains(err.Error(), "accepts 1 arg") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Delete subcommand tests
// ---------------------------------------------------------------------------

func TestPolicyDelete_Existing(t *testing.T) {
	resetPolicyFlags()
	store := newTestPolicyStore(t)

	seedPolicy(t, store, "to-delete")

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "delete", "to-delete"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("policy delete failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Deleted policy: to-delete") {
		t.Errorf("unexpected output: %q", output)
	}

	// Verify policy is gone.
	_, err = store.Get(context.Background(), "to-delete")
	if !errors.Is(err, pcrpolicy.ErrPolicyNotFound) {
		t.Errorf("expected policy to be deleted, got err: %v", err)
	}
}

func TestPolicyDelete_NotFound(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "delete", "ghost"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("error = %v, want %v", err, ErrPolicyNotFound)
	}
}

func TestPolicyDelete_MissingName(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "delete"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing name argument")
	}
}

func TestPolicyDelete_AutoUnsealProtection(t *testing.T) {
	resetPolicyFlags()
	store := newTestPolicyStore(t)
	ctx := context.Background()

	seedPolicy(t, store, "auto-locked")
	if err := store.SetAutoUnseal(ctx, "auto-locked"); err != nil {
		t.Fatalf("failed to set auto-unseal: %v", err)
	}

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "delete", "auto-locked"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrPolicyDeleteFailed) {
		t.Errorf("error = %v, want wrapping %v", err, ErrPolicyDeleteFailed)
	}
	if !strings.Contains(err.Error(), "auto-unseal") {
		t.Errorf("error message should mention auto-unseal: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Set-auto-unseal subcommand tests
// ---------------------------------------------------------------------------

func TestPolicySetAutoUnseal_Success(t *testing.T) {
	resetPolicyFlags()
	store := newTestPolicyStore(t)

	seedPolicy(t, store, "boot-auto")

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "set-auto-unseal", "boot-auto"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("set-auto-unseal failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Auto-unseal policy set: boot-auto") {
		t.Errorf("unexpected output: %q", output)
	}

	// Verify via store.
	entity, err := store.Get(context.Background(), "boot-auto")
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if !entity.AutoUnseal {
		t.Error("expected AutoUnseal to be true after set-auto-unseal")
	}
}

func TestPolicySetAutoUnseal_NotFound(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "set-auto-unseal", "nonexistent"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("error = %v, want %v", err, ErrPolicyNotFound)
	}
}

func TestPolicySetAutoUnseal_MissingName(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "set-auto-unseal"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing name argument")
	}
}

func TestPolicySetAutoUnseal_Replaces(t *testing.T) {
	resetPolicyFlags()
	store := newTestPolicyStore(t)
	ctx := context.Background()

	seedPolicy(t, store, "old-auto")
	seedPolicy(t, store, "new-auto")

	// Set old as auto-unseal.
	if err := store.SetAutoUnseal(ctx, "old-auto"); err != nil {
		t.Fatalf("failed to set auto-unseal: %v", err)
	}

	// Use CLI to set new one.
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "set-auto-unseal", "new-auto"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("set-auto-unseal failed: %v", err)
	}

	// Verify old is cleared.
	old, err := store.Get(ctx, "old-auto")
	if err != nil {
		t.Fatalf("failed to get old policy: %v", err)
	}
	if old.AutoUnseal {
		t.Error("expected old policy AutoUnseal to be false")
	}

	// Verify new is set.
	newP, err := store.Get(ctx, "new-auto")
	if err != nil {
		t.Fatalf("failed to get new policy: %v", err)
	}
	if !newP.AutoUnseal {
		t.Error("expected new policy AutoUnseal to be true")
	}
}

// ---------------------------------------------------------------------------
// Clear-auto-unseal subcommand tests
// ---------------------------------------------------------------------------

func TestPolicyClearAutoUnseal_Success(t *testing.T) {
	resetPolicyFlags()
	store := newTestPolicyStore(t)
	ctx := context.Background()

	seedPolicy(t, store, "was-auto")
	if err := store.SetAutoUnseal(ctx, "was-auto"); err != nil {
		t.Fatalf("failed to set auto-unseal: %v", err)
	}

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "clear-auto-unseal"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("clear-auto-unseal failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Auto-unseal policy cleared") {
		t.Errorf("unexpected output: %q", output)
	}

	// Verify no auto-unseal policy remains.
	entity, err := store.Get(ctx, "was-auto")
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if entity.AutoUnseal {
		t.Error("expected AutoUnseal to be false after clear")
	}
}

func TestPolicyClearAutoUnseal_NoneSet(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "clear-auto-unseal"})

	// Clearing when none is set should be a no-op success.
	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("clear-auto-unseal should not fail when none set: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Refresh subcommand tests
// ---------------------------------------------------------------------------

func TestPolicyRefresh_NotFound(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "refresh", "ghost"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("error = %v, want %v", err, ErrPolicyNotFound)
	}
}

func TestPolicyRefresh_MissingName(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "refresh"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing name argument")
	}
}

// ---------------------------------------------------------------------------
// Verify subcommand tests
// ---------------------------------------------------------------------------

func TestPolicyVerify_NotFound(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "verify", "ghost"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("error = %v, want %v", err, ErrPolicyNotFound)
	}
}

func TestPolicyVerify_MissingName(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "verify"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing name argument")
	}
}

// ---------------------------------------------------------------------------
// Export subcommand tests
// ---------------------------------------------------------------------------

func TestPolicyExport_Existing(t *testing.T) {
	resetPolicyFlags()
	store := newTestPolicyStore(t)

	seedPolicy(t, store, "export-me")

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "export", "export-me"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("policy export failed: %v", err)
	}

	var exported policyExportJSON
	if err := json.Unmarshal(buf.Bytes(), &exported); err != nil {
		t.Fatalf("failed to parse exported JSON: %v (output: %q)", err, buf.String())
	}

	if exported.Name != "export-me" {
		t.Errorf("exported name = %q, want %q", exported.Name, "export-me")
	}
	if exported.Bank != "SHA256" {
		t.Errorf("exported bank = %q, want %q", exported.Bank, "SHA256")
	}
	if len(exported.PCRs) != 2 {
		t.Errorf("exported PCRs count = %d, want 2", len(exported.PCRs))
	}
}

func TestPolicyExport_ValidJSON(t *testing.T) {
	resetPolicyFlags()
	store := newTestPolicyStore(t)

	seedPolicy(t, store, "json-test")

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "export", "json-test"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("policy export failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("export output is not valid JSON: %v", err)
	}

	requiredKeys := []string{"name", "bank", "pcrs", "auto_unseal", "created_at", "updated_at"}
	for _, key := range requiredKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("exported JSON missing key %q", key)
		}
	}
}

func TestPolicyExport_NotFound(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "export", "ghost"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("error = %v, want %v", err, ErrPolicyNotFound)
	}
}

func TestPolicyExport_MissingName(t *testing.T) {
	resetPolicyFlags()
	_ = newTestPolicyStore(t)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"policy", "export"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing name argument")
	}
}

// ---------------------------------------------------------------------------
// Conversion helper tests
// ---------------------------------------------------------------------------

func TestUintSliceToIntSlice(t *testing.T) {
	input := []uint{0, 1, 7, 23}
	result := uintSliceToIntSlice(input)

	if len(result) != len(input) {
		t.Fatalf("length = %d, want %d", len(result), len(input))
	}

	for i, v := range result {
		if v != int(input[i]) {
			t.Errorf("result[%d] = %d, want %d", i, v, input[i])
		}
	}
}

func TestUintSliceToIntSlice_Empty(t *testing.T) {
	result := uintSliceToIntSlice([]uint{})
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %v", result)
	}
}

func TestIntSliceToUintSlice(t *testing.T) {
	input := []int{0, 1, 7, 23}
	result := intSliceToUintSlice(input)

	if len(result) != len(input) {
		t.Fatalf("length = %d, want %d", len(result), len(input))
	}

	for i, v := range result {
		if v != uint(input[i]) {
			t.Errorf("result[%d] = %d, want %d", i, v, input[i])
		}
	}
}

func TestIntSliceToUintSlice_Empty(t *testing.T) {
	result := intSliceToUintSlice([]int{})
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// PCR value comparison tests
// ---------------------------------------------------------------------------

func TestComparePCRByteValues_AllMatch(t *testing.T) {
	expected := map[uint][]byte{
		0: {0xAA, 0xBB},
		7: {0xCC, 0xDD},
	}
	current := map[uint][]byte{
		0: {0xAA, 0xBB},
		7: {0xCC, 0xDD},
	}

	mismatches := comparePCRByteValues(expected, current)
	if len(mismatches) != 0 {
		t.Errorf("expected 0 mismatches, got %d", len(mismatches))
	}
}

func TestComparePCRByteValues_Mismatch(t *testing.T) {
	expected := map[uint][]byte{
		0: {0xAA, 0xBB},
		7: {0xCC, 0xDD},
	}
	current := map[uint][]byte{
		0: {0xAA, 0xBB},
		7: {0xFF, 0xFF},
	}

	mismatches := comparePCRByteValues(expected, current)
	if len(mismatches) != 1 {
		t.Fatalf("expected 1 mismatch, got %d", len(mismatches))
	}
	if mismatches[0].index != 7 {
		t.Errorf("mismatch index = %d, want 7", mismatches[0].index)
	}
}

func TestComparePCRByteValues_MissingInCurrent(t *testing.T) {
	expected := map[uint][]byte{
		0: {0xAA},
		7: {0xBB},
	}
	current := map[uint][]byte{
		0: {0xAA},
	}

	mismatches := comparePCRByteValues(expected, current)
	if len(mismatches) != 1 {
		t.Fatalf("expected 1 mismatch, got %d", len(mismatches))
	}
	if mismatches[0].index != 7 {
		t.Errorf("mismatch index = %d, want 7", mismatches[0].index)
	}
}

func TestComparePCRByteValues_EmptyMaps(t *testing.T) {
	mismatches := comparePCRByteValues(map[uint][]byte{}, map[uint][]byte{})
	if len(mismatches) != 0 {
		t.Errorf("expected 0 mismatches for empty maps, got %d", len(mismatches))
	}
}

func TestComparePCRByteValues_Sorted(t *testing.T) {
	expected := map[uint][]byte{
		14: {0xAA},
		2:  {0xBB},
		0:  {0xCC},
	}
	current := map[uint][]byte{
		14: {0xFF},
		2:  {0xFF},
		0:  {0xFF},
	}

	mismatches := comparePCRByteValues(expected, current)
	if len(mismatches) != 3 {
		t.Fatalf("expected 3 mismatches, got %d", len(mismatches))
	}
	if mismatches[0].index != 0 || mismatches[1].index != 2 || mismatches[2].index != 14 {
		t.Errorf("mismatches not sorted: %v", mismatches)
	}
}

// ---------------------------------------------------------------------------
// Hex conversion helper tests
// ---------------------------------------------------------------------------

func TestHexMapToBytes(t *testing.T) {
	input := map[int]string{
		0: "aabbccdd",
		7: "deadbeef",
	}

	result := hexMapToBytes(input)
	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}

	expected0 := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	for i, b := range result[0] {
		if b != expected0[i] {
			t.Errorf("result[0][%d] = %x, want %x", i, b, expected0[i])
		}
	}
}

func TestBytesMapToHex(t *testing.T) {
	input := map[uint][]byte{
		0: {0xAA, 0xBB, 0xCC, 0xDD},
		7: {0xDE, 0xAD, 0xBE, 0xEF},
	}

	result := bytesMapToHex(input)
	if result[0] != "aabbccdd" {
		t.Errorf("result[0] = %q, want %q", result[0], "aabbccdd")
	}
	if result[7] != "deadbeef" {
		t.Errorf("result[7] = %q, want %q", result[7], "deadbeef")
	}
}

func TestFormatPCRIndices(t *testing.T) {
	pcrs := map[uint][]byte{
		7: {0x01},
		0: {0x02},
		4: {0x03},
	}

	result := formatPCRIndices(pcrs)
	if result != "0, 4, 7" {
		t.Errorf("formatPCRIndices = %q, want %q", result, "0, 4, 7")
	}
}

func TestFormatPCRIndices_Empty(t *testing.T) {
	result := formatPCRIndices(map[uint][]byte{})
	if result != "" {
		t.Errorf("formatPCRIndices(empty) = %q, want %q", result, "")
	}
}

func TestSortedPCRIndices(t *testing.T) {
	pcrs := map[uint][]byte{
		14: {0x01},
		0:  {0x02},
		7:  {0x03},
		2:  {0x04},
	}

	indices := sortedPCRIndices(pcrs)
	expected := []uint{0, 2, 7, 14}
	if len(indices) != len(expected) {
		t.Fatalf("length = %d, want %d", len(indices), len(expected))
	}
	for i, idx := range indices {
		if idx != expected[i] {
			t.Errorf("indices[%d] = %d, want %d", i, idx, expected[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Valid PCR banks tests
// ---------------------------------------------------------------------------

func TestValidPCRBanks(t *testing.T) {
	for _, bank := range []string{"sha1", "sha256", "sha384"} {
		if !validPCRBanks[bank] {
			t.Errorf("bank %q should be valid", bank)
		}
	}
}

func TestInvalidPCRBanks(t *testing.T) {
	for _, bank := range []string{"md5", "sha3", "SHA256", "sha512", ""} {
		if validPCRBanks[bank] {
			t.Errorf("bank %q should be invalid", bank)
		}
	}
}

// Ensure dao.PageQuery is used to avoid unused import.
var _ = dao.PageQuery{}
