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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/pflag"
)

// resetPasswordFlags resets all password subcommand flags to their default
// values. This is necessary because Cobra retains flag state across
// RootCmd.Execute() calls within the same process, which causes test
// pollution when multiple tests modify the same flags.
func resetPasswordFlags() {
	cmds := []*pflag.FlagSet{
		passwordAddCmd.Flags(),
		passwordListCmd.Flags(),
		passwordGetCmd.Flags(),
		passwordRemoveCmd.Flags(),
		passwordUnlockCmd.Flags(),
		passwordLockCmd.Flags(),
		passwordStatusCmd.Flags(),
		passwordAccessModeCmd.Flags(),
	}
	for _, fs := range cmds {
		fs.VisitAll(func(f *pflag.Flag) {
			f.Changed = false
			_ = f.Value.Set(f.DefValue)
		})
	}
}

// mockPasswordStoreClient implements PasswordStoreClientService for testing.
type mockPasswordStoreClient struct {
	mu            sync.Mutex
	accessMode    string
	isLocked      bool
	autoUnsealed  bool
	passwordCount int
	connectErr    error
	unlockErr     error
	lockErr       error
	statusErr     error
	setModeErr    error

	// Track calls for verification.
	unlockCalls  int
	lockCalls    int
	statusCalls  int
	setModeCalls int

	// Track the last PIN passed to unlock.
	lastUnlockPIN string

	// Track the last mode passed to set-access-mode.
	lastSetMode string
}

func newMockPasswordStoreClient() *mockPasswordStoreClient {
	return &mockPasswordStoreClient{
		accessMode:    AccessModePINPerOperation,
		isLocked:      true,
		autoUnsealed:  false,
		passwordCount: 5,
	}
}

func (m *mockPasswordStoreClient) Connect(_ context.Context) error {
	return m.connectErr
}

func (m *mockPasswordStoreClient) Close() error {
	return nil
}

func (m *mockPasswordStoreClient) PasswordStoreUnlock(_ context.Context, req *transport.PasswordStoreUnlockRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unlockCalls++
	m.lastUnlockPIN = req.UserPIN
	if m.unlockErr != nil {
		return m.unlockErr
	}
	m.isLocked = false
	return nil
}

func (m *mockPasswordStoreClient) PasswordStoreLock(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lockCalls++
	if m.lockErr != nil {
		return m.lockErr
	}
	m.isLocked = true
	return nil
}

func (m *mockPasswordStoreClient) PasswordStoreStatus(_ context.Context) (*transport.PasswordStoreStatusResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statusCalls++
	if m.statusErr != nil {
		return nil, m.statusErr
	}
	return &transport.PasswordStoreStatusResponse{
		AccessMode:    m.accessMode,
		IsLocked:      m.isLocked,
		AutoUnsealed:  m.autoUnsealed,
		PasswordCount: m.passwordCount,
	}, nil
}

func (m *mockPasswordStoreClient) PasswordStoreSetAccessMode(_ context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setModeCalls++
	m.lastSetMode = req.Mode
	if m.setModeErr != nil {
		return m.setModeErr
	}
	m.accessMode = req.Mode
	return nil
}

// withMockPasswordClient injects a mock password client factory for the duration
// of a test and restores the original factory on cleanup.
func withMockPasswordClient(t *testing.T, mock *mockPasswordStoreClient) {
	t.Helper()
	original := passwordClientFactory
	passwordClientFactory = func() (PasswordStoreClientService, error) {
		return mock, nil
	}
	t.Cleanup(func() {
		passwordClientFactory = original
	})
}

// withFailingPasswordClientFactory injects a factory that returns an error.
func withFailingPasswordClientFactory(t *testing.T, err error) {
	t.Helper()
	original := passwordClientFactory
	passwordClientFactory = func() (PasswordStoreClientService, error) {
		return nil, err
	}
	t.Cleanup(func() {
		passwordClientFactory = original
	})
}

// --- Existing Tests ---

func TestPasswordCmd_Help(t *testing.T) {
	resetPasswordFlags()

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("password --help failed: %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"password",
		"static",
		"add",
		"list",
		"get",
		"remove",
		"unlock",
		"lock",
		"status",
		"access-mode",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(strings.ToLower(output), strings.ToLower(expected)) {
			t.Errorf("password help output missing %q", expected)
		}
	}
}

func TestPasswordCmd_SubcommandRegistration(t *testing.T) {
	subcommands := map[string]bool{
		"add":         false,
		"list":        false,
		"get":         false,
		"remove":      false,
		"unlock":      false,
		"lock":        false,
		"status":      false,
		"access-mode": false,
	}

	for _, cmd := range PasswordCmd.Commands() {
		if _, ok := subcommands[cmd.Name()]; ok {
			subcommands[cmd.Name()] = true
		}
	}

	for name, found := range subcommands {
		if !found {
			t.Errorf("password subcommand %q not registered", name)
		}
	}
}

func TestPasswordCmd_AddMissingName(t *testing.T) {
	resetPasswordFlags()

	storePath, err := os.MkdirTemp("", "pw-test-add-missing-name-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(storePath) })

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "add", "--password", "test", "--store", storePath})

	err = RootCmd.Execute()
	if err != ErrPasswordMissingName {
		t.Errorf("password add without --name: error = %v, want %v", err, ErrPasswordMissingName)
	}
}

func TestPasswordCmd_AddMissingSource(t *testing.T) {
	resetPasswordFlags()

	storePath, err := os.MkdirTemp("", "pw-test-add-missing-source-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(storePath) })

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "add", "--name", "test", "--store", storePath})

	err = RootCmd.Execute()
	if err != ErrPasswordMissingSource {
		t.Errorf("password add without --password or --generate: error = %v, want %v", err, ErrPasswordMissingSource)
	}
}

func TestPasswordCmd_AddMutuallyExclusive(t *testing.T) {
	resetPasswordFlags()

	storePath, err := os.MkdirTemp("", "pw-test-add-mutex-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(storePath) })

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{
		"password", "add",
		"--name", "test",
		"--password", "pw",
		"--generate",
		"--store", storePath,
	})

	err = RootCmd.Execute()
	if err != ErrPasswordMutuallyExclusive {
		t.Errorf("password add with --password and --generate: error = %v, want %v", err, ErrPasswordMutuallyExclusive)
	}
}

func TestPasswordCmd_GetMissingArg(t *testing.T) {
	resetPasswordFlags()

	storePath, err := os.MkdirTemp("", "pw-test-get-missing-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(storePath) })

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "get", "--store", storePath})

	err = RootCmd.Execute()
	if err != ErrPasswordMissingGetArg {
		t.Errorf("password get with no args: error = %v, want %v", err, ErrPasswordMissingGetArg)
	}
}

func TestPasswordCmd_RemoveMissingArg(t *testing.T) {
	resetPasswordFlags()

	storePath, err := os.MkdirTemp("", "pw-test-remove-missing-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(storePath) })

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "remove", "--force", "--store", storePath})

	err = RootCmd.Execute()
	if err != ErrPasswordMissingRemoveArg {
		t.Errorf("password remove with no args: error = %v, want %v", err, ErrPasswordMissingRemoveArg)
	}
}

func TestPasswordErrors(t *testing.T) {
	errs := []error{
		ErrPasswordMissingName,
		ErrPasswordMissingSource,
		ErrPasswordMutuallyExclusive,
		ErrPasswordMissingGetArg,
		ErrPasswordMissingRemoveArg,
		ErrPasswordStoreOpenFailed,
		ErrPasswordAddFailed,
		ErrPasswordListFailed,
		ErrPasswordGetFailed,
		ErrPasswordDeleteFailed,
		ErrPasswordGenerateFailed,
		ErrPasswordNotFound,
		ErrPasswordUnlockFailed,
		ErrPasswordLockFailed,
		ErrPasswordStatusFailed,
		ErrPasswordAccessModeFailed,
		ErrPasswordInvalidMode,
		ErrPasswordMissingMode,
		ErrPasswordMissingPIN,
		ErrPasswordConnectFailed,
	}

	for _, err := range errs {
		if err.Error() == "" {
			t.Errorf("password error has empty message: %v", err)
		}
		if !strings.HasPrefix(err.Error(), "password:") {
			t.Errorf("password error missing 'password:' prefix: %v", err)
		}
	}
}

func TestPasswordCmd_AddAndList(t *testing.T) {
	resetPasswordFlags()

	storePath, err := os.MkdirTemp("", "pw-test-add-list-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(storePath) })

	// Add a password entry via RootCmd.
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{
		"password", "add",
		"--name", "TestService",
		"--password", "s3cretP@ss!",
		"--store", storePath,
	})

	err = RootCmd.Execute()
	if err != nil {
		t.Fatalf("password add failed: %v", err)
	}

	// Verify the entry was persisted to the store by opening
	// the backend directly and reading it back.
	backend, err := file.New(storePath)
	if err != nil {
		t.Fatalf("failed to open store backend: %v", err)
	}
	store := staticpw.NewStore(backend)
	defer func() { _ = store.Close() }()

	pw, err := store.Get("TestService")
	if err != nil {
		t.Fatalf("store.Get(TestService) failed: %v", err)
	}
	if pw.Name != "TestService" {
		t.Errorf("stored entry name = %q, want %q", pw.Name, "TestService")
	}
	if pw.Password != "s3cretP@ss!" {
		t.Errorf("stored entry password = %q, want %q", pw.Password, "s3cretP@ss!")
	}

	// Verify list returns the entry.
	passwords, err := store.List()
	if err != nil {
		t.Fatalf("store.List() failed: %v", err)
	}
	if len(passwords) != 1 {
		t.Fatalf("store.List() returned %d entries, want 1", len(passwords))
	}
	if passwords[0].Name != "TestService" {
		t.Errorf("listed entry name = %q, want %q", passwords[0].Name, "TestService")
	}
}

func TestPasswordCmd_AddGenerated(t *testing.T) {
	resetPasswordFlags()

	storePath, err := os.MkdirTemp("", "pw-test-add-gen-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(storePath) })

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{
		"password", "add",
		"--name", "GeneratedEntry",
		"--generate",
		"--store", storePath,
	})

	err = RootCmd.Execute()
	if err != nil {
		t.Fatalf("password add --generate failed: %v", err)
	}

	// Verify the generated entry was persisted to the store.
	backend, err := file.New(storePath)
	if err != nil {
		t.Fatalf("failed to open store backend: %v", err)
	}
	store := staticpw.NewStore(backend)
	defer func() { _ = store.Close() }()

	pw, err := store.Get("GeneratedEntry")
	if err != nil {
		t.Fatalf("store.Get(GeneratedEntry) failed: %v", err)
	}
	if pw.Name != "GeneratedEntry" {
		t.Errorf("stored entry name = %q, want %q", pw.Name, "GeneratedEntry")
	}
	if pw.Password == "" {
		t.Error("generated password is empty")
	}

	// The default generated password length is 32 characters.
	if len(pw.Password) != staticpw.DefaultLength {
		t.Errorf("generated password length = %d, want %d", len(pw.Password), staticpw.DefaultLength)
	}

	// Verify the entry file exists on disk. The staticpw store uses an
	// xxhash-based ID as the filename, not the entry name.
	entryID := staticpw.GenerateID("GeneratedEntry", "")
	entryPath := filepath.Join(storePath, "staticpw", entryID+".json")
	if _, statErr := os.Stat(entryPath); os.IsNotExist(statErr) {
		t.Errorf("generated entry file not found at %s", entryPath)
	}
}

// --- Add with metadata flags tests ---

func TestPasswordCmd_AddWithMetadata(t *testing.T) {
	resetPasswordFlags()

	storePath, err := os.MkdirTemp("", "pw-test-add-meta-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(storePath) })

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{
		"password", "add",
		"--name", "GitHubWork",
		"--password", "gh_tok_abc123",
		"--title", "GitHub (Work)",
		"--username", "jdoe",
		"--url", "https://github.com",
		"--notes", "Work account",
		"--store", storePath,
	})

	err = RootCmd.Execute()
	if err != nil {
		t.Fatalf("password add with metadata failed: %v", err)
	}

	// Verify all fields were persisted.
	backend, err := file.New(storePath)
	if err != nil {
		t.Fatalf("failed to open store backend: %v", err)
	}
	store := staticpw.NewStore(backend)
	defer func() { _ = store.Close() }()

	pw, err := store.Get("GitHubWork")
	if err != nil {
		t.Fatalf("store.Get(GitHubWork) failed: %v", err)
	}
	if pw.Name != "GitHubWork" {
		t.Errorf("stored entry name = %q, want %q", pw.Name, "GitHubWork")
	}
	if pw.Password != "gh_tok_abc123" {
		t.Errorf("stored entry password = %q, want %q", pw.Password, "gh_tok_abc123")
	}
	if pw.Title != "GitHub (Work)" {
		t.Errorf("stored entry title = %q, want %q", pw.Title, "GitHub (Work)")
	}
	if pw.Username != "jdoe" {
		t.Errorf("stored entry username = %q, want %q", pw.Username, "jdoe")
	}
	if pw.URL != "https://github.com" {
		t.Errorf("stored entry url = %q, want %q", pw.URL, "https://github.com")
	}
	if pw.Notes != "Work account" {
		t.Errorf("stored entry notes = %q, want %q", pw.Notes, "Work account")
	}
}

func TestPasswordCmd_AddWithoutMetadata(t *testing.T) {
	resetPasswordFlags()

	storePath, err := os.MkdirTemp("", "pw-test-add-nometa-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(storePath) })

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{
		"password", "add",
		"--name", "SimplePW",
		"--password", "simple123",
		"--store", storePath,
	})

	err = RootCmd.Execute()
	if err != nil {
		t.Fatalf("password add without metadata failed: %v", err)
	}

	// Verify optional metadata fields default to empty.
	backend, err := file.New(storePath)
	if err != nil {
		t.Fatalf("failed to open store backend: %v", err)
	}
	store := staticpw.NewStore(backend)
	defer func() { _ = store.Close() }()

	pw, err := store.Get("SimplePW")
	if err != nil {
		t.Fatalf("store.Get(SimplePW) failed: %v", err)
	}
	if pw.Title != "" {
		t.Errorf("stored entry title = %q, want empty", pw.Title)
	}
	if pw.Username != "" {
		t.Errorf("stored entry username = %q, want empty", pw.Username)
	}
	if pw.URL != "" {
		t.Errorf("stored entry url = %q, want empty", pw.URL)
	}
}

// --- Unlock Subcommand Tests ---

func TestPasswordCmd_Unlock(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "unlock", "--pin", "1234"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("password unlock failed: %v", err)
	}

	if mock.unlockCalls != 1 {
		t.Errorf("PasswordStoreUnlock called %d times, want 1", mock.unlockCalls)
	}

	if mock.lastUnlockPIN != "1234" {
		t.Errorf("unlock PIN = %q, want %q", mock.lastUnlockPIN, "1234")
	}

	if mock.isLocked {
		t.Error("store should be unlocked after unlock command")
	}

	output := buf.String()
	if !strings.Contains(output, "Password store unlocked.") {
		t.Errorf("unlock output missing confirmation, got: %q", output)
	}
}

func TestPasswordCmd_UnlockMissingPIN(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "unlock"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrPasswordMissingPIN) {
		t.Errorf("unlock without --pin: error = %v, want %v", err, ErrPasswordMissingPIN)
	}

	if mock.unlockCalls != 0 {
		t.Errorf("PasswordStoreUnlock should not have been called, was called %d times", mock.unlockCalls)
	}
}

func TestPasswordCmd_UnlockServerError(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	mock.unlockErr = errors.New("invalid PIN")
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "unlock", "--pin", "wrong"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("unlock with server error should fail")
	}
	if !errors.Is(err, ErrPasswordUnlockFailed) {
		t.Errorf("unlock server error: error = %v, want wrapping %v", err, ErrPasswordUnlockFailed)
	}
}

func TestPasswordCmd_UnlockConnectError(t *testing.T) {
	resetPasswordFlags()
	withFailingPasswordClientFactory(t, errors.New("no server"))

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "unlock", "--pin", "1234"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("unlock with connection error should fail")
	}
	if !errors.Is(err, ErrPasswordConnectFailed) {
		t.Errorf("unlock connect error: error = %v, want wrapping %v", err, ErrPasswordConnectFailed)
	}
}

// --- Lock Subcommand Tests ---

func TestPasswordCmd_Lock(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	mock.isLocked = false
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "lock"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("password lock failed: %v", err)
	}

	if mock.lockCalls != 1 {
		t.Errorf("PasswordStoreLock called %d times, want 1", mock.lockCalls)
	}

	if !mock.isLocked {
		t.Error("store should be locked after lock command")
	}

	output := buf.String()
	if !strings.Contains(output, "Password store locked.") {
		t.Errorf("lock output missing confirmation, got: %q", output)
	}
}

func TestPasswordCmd_LockServerError(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	mock.lockErr = errors.New("lock failed")
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "lock"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("lock with server error should fail")
	}
	if !errors.Is(err, ErrPasswordLockFailed) {
		t.Errorf("lock server error: error = %v, want wrapping %v", err, ErrPasswordLockFailed)
	}
}

func TestPasswordCmd_LockConnectError(t *testing.T) {
	resetPasswordFlags()
	withFailingPasswordClientFactory(t, errors.New("no server"))

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "lock"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("lock with connection error should fail")
	}
	if !errors.Is(err, ErrPasswordConnectFailed) {
		t.Errorf("lock connect error: error = %v, want wrapping %v", err, ErrPasswordConnectFailed)
	}
}

// --- Status Subcommand Tests ---

func TestPasswordCmd_Status(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	mock.accessMode = AccessModeSessionBased
	mock.isLocked = false
	mock.autoUnsealed = true
	mock.passwordCount = 12
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "status"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("password status failed: %v", err)
	}

	if mock.statusCalls != 1 {
		t.Errorf("PasswordStoreStatus called %d times, want 1", mock.statusCalls)
	}

	output := buf.String()
	if !strings.Contains(output, "Password Store Status:") {
		t.Errorf("status output missing header, got: %q", output)
	}
	if !strings.Contains(output, "Access Mode:     session_based") {
		t.Errorf("status output missing Access Mode, got: %q", output)
	}
	if !strings.Contains(output, "Locked:          false") {
		t.Errorf("status output missing Locked, got: %q", output)
	}
	if !strings.Contains(output, "Auto-Unsealed:   true") {
		t.Errorf("status output missing Auto-Unsealed, got: %q", output)
	}
	if !strings.Contains(output, "Password Count:  12") {
		t.Errorf("status output missing Password Count, got: %q", output)
	}
}

func TestPasswordCmd_StatusLocked(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	mock.accessMode = AccessModePINPerOperation
	mock.isLocked = true
	mock.autoUnsealed = false
	mock.passwordCount = 0
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "status"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("password status (locked) failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Access Mode:     pin_per_operation") {
		t.Errorf("status output missing Access Mode, got: %q", output)
	}
	if !strings.Contains(output, "Locked:          true") {
		t.Errorf("status output missing Locked, got: %q", output)
	}
	if !strings.Contains(output, "Auto-Unsealed:   false") {
		t.Errorf("status output missing Auto-Unsealed, got: %q", output)
	}
	if !strings.Contains(output, "Password Count:  0") {
		t.Errorf("status output missing Password Count, got: %q", output)
	}
}

func TestPasswordCmd_StatusServerError(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	mock.statusErr = errors.New("server down")
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "status"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("status with server error should fail")
	}
	if !errors.Is(err, ErrPasswordStatusFailed) {
		t.Errorf("status server error: error = %v, want wrapping %v", err, ErrPasswordStatusFailed)
	}
}

func TestPasswordCmd_StatusConnectError(t *testing.T) {
	resetPasswordFlags()
	withFailingPasswordClientFactory(t, errors.New("no server"))

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "status"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("status with connection error should fail")
	}
	if !errors.Is(err, ErrPasswordConnectFailed) {
		t.Errorf("status connect error: error = %v, want wrapping %v", err, ErrPasswordConnectFailed)
	}
}

// --- Access-Mode Subcommand Tests ---

func TestPasswordCmd_AccessModeSessionBased(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "access-mode", "--mode", "session_based"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("password access-mode failed: %v", err)
	}

	if mock.setModeCalls != 1 {
		t.Errorf("PasswordStoreSetAccessMode called %d times, want 1", mock.setModeCalls)
	}

	if mock.lastSetMode != AccessModeSessionBased {
		t.Errorf("set mode = %q, want %q", mock.lastSetMode, AccessModeSessionBased)
	}

	if mock.accessMode != AccessModeSessionBased {
		t.Errorf("access mode = %q, want %q", mock.accessMode, AccessModeSessionBased)
	}

	output := buf.String()
	if !strings.Contains(output, "Access mode set to: session_based") {
		t.Errorf("access-mode output missing confirmation, got: %q", output)
	}
}

func TestPasswordCmd_AccessModePINPerOperation(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	mock.accessMode = AccessModeSessionBased
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "access-mode", "--mode", "pin_per_operation"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("password access-mode failed: %v", err)
	}

	if mock.accessMode != AccessModePINPerOperation {
		t.Errorf("access mode = %q, want %q", mock.accessMode, AccessModePINPerOperation)
	}

	output := buf.String()
	if !strings.Contains(output, "Access mode set to: pin_per_operation") {
		t.Errorf("access-mode output missing confirmation, got: %q", output)
	}
}

func TestPasswordCmd_AccessModeMissingMode(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "access-mode"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrPasswordMissingMode) {
		t.Errorf("access-mode without --mode: error = %v, want %v", err, ErrPasswordMissingMode)
	}

	if mock.setModeCalls != 0 {
		t.Errorf("PasswordStoreSetAccessMode should not have been called, was called %d times", mock.setModeCalls)
	}
}

func TestPasswordCmd_AccessModeInvalidMode(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "access-mode", "--mode", "invalid_mode"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrPasswordInvalidMode) {
		t.Errorf("access-mode with invalid mode: error = %v, want %v", err, ErrPasswordInvalidMode)
	}

	if mock.setModeCalls != 0 {
		t.Errorf("PasswordStoreSetAccessMode should not have been called, was called %d times", mock.setModeCalls)
	}
}

func TestPasswordCmd_AccessModeServerError(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	mock.setModeErr = errors.New("access denied")
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "access-mode", "--mode", "session_based"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("access-mode with server error should fail")
	}
	if !errors.Is(err, ErrPasswordAccessModeFailed) {
		t.Errorf("access-mode server error: error = %v, want wrapping %v", err, ErrPasswordAccessModeFailed)
	}
}

func TestPasswordCmd_AccessModeConnectError(t *testing.T) {
	resetPasswordFlags()
	withFailingPasswordClientFactory(t, errors.New("no server"))

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "access-mode", "--mode", "session_based"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("access-mode with connection error should fail")
	}
	if !errors.Is(err, ErrPasswordConnectFailed) {
		t.Errorf("access-mode connect error: error = %v, want wrapping %v", err, ErrPasswordConnectFailed)
	}
}

// --- Unlock/Lock Roundtrip Test ---

func TestPasswordCmd_UnlockLockRoundtrip(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	withMockPasswordClient(t, mock)

	// Verify store starts locked.
	if !mock.isLocked {
		t.Fatal("store should start locked")
	}

	// Unlock the store.
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "unlock", "--pin", "mypin"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unlock failed: %v", err)
	}

	if mock.isLocked {
		t.Error("store should be unlocked after unlock")
	}

	// Lock the store.
	resetPasswordFlags()
	buf.Reset()
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "lock"})

	err = RootCmd.Execute()
	if err != nil {
		t.Fatalf("lock failed: %v", err)
	}

	if !mock.isLocked {
		t.Error("store should be locked after lock")
	}

	if mock.unlockCalls != 1 {
		t.Errorf("unlock calls = %d, want 1", mock.unlockCalls)
	}
	if mock.lockCalls != 1 {
		t.Errorf("lock calls = %d, want 1", mock.lockCalls)
	}
}

// --- PasswordStoreError Type Tests ---

func TestPasswordStoreError_ErrorFormats(t *testing.T) {
	tests := []struct {
		name     string
		err      *PasswordStoreError
		expected string
	}{
		{
			name:     "operation only",
			err:      &PasswordStoreError{Operation: "test"},
			expected: "password: test",
		},
		{
			name:     "operation with message",
			err:      &PasswordStoreError{Operation: "test", Message: "some message"},
			expected: "password: test: some message",
		},
		{
			name:     "operation with error",
			err:      &PasswordStoreError{Operation: "test", Err: errors.New("inner")},
			expected: "password: test: inner",
		},
		{
			name:     "operation with message and error",
			err:      &PasswordStoreError{Operation: "test", Message: "context", Err: errors.New("inner")},
			expected: "password: test: context: inner",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestPasswordStoreError_Unwrap(t *testing.T) {
	inner := errors.New("inner error")
	pErr := &PasswordStoreError{Operation: "test", Err: inner}

	if pErr.Unwrap() != inner {
		t.Errorf("Unwrap() = %v, want %v", pErr.Unwrap(), inner)
	}

	noInner := &PasswordStoreError{Operation: "test"}
	if noInner.Unwrap() != nil {
		t.Errorf("Unwrap() on error without inner = %v, want nil", noInner.Unwrap())
	}
}

// --- Access Mode Constants Tests ---

func TestAccessModeConstants(t *testing.T) {
	if AccessModePINPerOperation != "pin_per_operation" {
		t.Errorf("AccessModePINPerOperation = %q, want %q", AccessModePINPerOperation, "pin_per_operation")
	}
	if AccessModeSessionBased != "session_based" {
		t.Errorf("AccessModeSessionBased = %q, want %q", AccessModeSessionBased, "session_based")
	}
}

// --- Default Factory Error Tests ---

func TestDefaultPasswordClientFactory_MissingURL(t *testing.T) {
	// Save and clear the xkmsdURL.
	original := xkmsdURL
	xkmsdURL = ""
	defer func() { xkmsdURL = original }()

	_, err := defaultPasswordClientFactory()
	if err == nil {
		t.Fatal("defaultPasswordClientFactory with empty URL should fail")
	}

	var storeErr *PasswordStoreError
	if !errors.As(err, &storeErr) {
		t.Fatalf("error should be *PasswordStoreError, got %T", err)
	}
	if storeErr.Operation != "connect" {
		t.Errorf("error operation = %q, want %q", storeErr.Operation, "connect")
	}
}

func TestDefaultPasswordClientFactory_WithURL(t *testing.T) {
	// Save and set the xkmsdURL.
	original := xkmsdURL
	xkmsdURL = "http://localhost:8080"
	defer func() { xkmsdURL = original }()

	_, err := defaultPasswordClientFactory()
	if err == nil {
		t.Fatal("defaultPasswordClientFactory should fail (no real server)")
	}

	var storeErr *PasswordStoreError
	if !errors.As(err, &storeErr) {
		t.Fatalf("error should be *PasswordStoreError, got %T", err)
	}
	if storeErr.Operation != "connect" {
		t.Errorf("error operation = %q, want %q", storeErr.Operation, "connect")
	}
}

// --- Status After Mode Change Integration Test ---

func TestPasswordCmd_AccessModeThenStatus(t *testing.T) {
	resetPasswordFlags()
	mock := newMockPasswordStoreClient()
	withMockPasswordClient(t, mock)

	// Set mode to session_based.
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "access-mode", "--mode", "session_based"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("access-mode failed: %v", err)
	}

	// Check status reflects the change.
	resetPasswordFlags()
	buf.Reset()
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "status"})

	err = RootCmd.Execute()
	if err != nil {
		t.Fatalf("status failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Access Mode:     session_based") {
		t.Errorf("status should reflect session_based mode, got: %q", output)
	}
}
