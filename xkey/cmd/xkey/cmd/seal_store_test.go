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

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/pflag"
)

// mockSealStoreClient implements SealStoreService for testing.
type mockSealStoreClient struct {
	mu         sync.Mutex
	secrets    map[string][]byte
	putErr     error
	getErr     error
	delErr     error
	listErr    error
	resealErr  error
	statusErr  error
	connectErr error

	// Track calls for verification.
	putCalls    int
	getCalls    int
	delCalls    int
	listCalls   int
	resealCalls int
	statusCalls int
}

func newMockSealStoreClient() *mockSealStoreClient {
	return &mockSealStoreClient{
		secrets: make(map[string][]byte),
	}
}

func (m *mockSealStoreClient) Connect(_ context.Context) error {
	return m.connectErr
}

func (m *mockSealStoreClient) Close() error {
	return nil
}

func (m *mockSealStoreClient) SealStorePut(_ context.Context, req *transport.SealStorePutRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.putCalls++
	if m.putErr != nil {
		return m.putErr
	}
	m.secrets[req.Name] = req.Secret
	return nil
}

func (m *mockSealStoreClient) SealStoreGet(_ context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCalls++
	if m.getErr != nil {
		return nil, m.getErr
	}
	secret, ok := m.secrets[req.Name]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return &transport.SealStoreGetResponse{
		Name:   req.Name,
		Secret: secret,
	}, nil
}

func (m *mockSealStoreClient) SealStoreDelete(_ context.Context, req *transport.SealStoreDeleteRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delCalls++
	if m.delErr != nil {
		return m.delErr
	}
	delete(m.secrets, req.Name)
	return nil
}

func (m *mockSealStoreClient) SealStoreList(_ context.Context) (*transport.SealStoreListResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listCalls++
	if m.listErr != nil {
		return nil, m.listErr
	}
	names := make([]string, 0, len(m.secrets))
	for name := range m.secrets {
		names = append(names, name)
	}
	return &transport.SealStoreListResponse{
		Names: names,
	}, nil
}

func (m *mockSealStoreClient) SealStoreReseal(_ context.Context, req *transport.SealStoreResealRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resealCalls++
	if m.resealErr != nil {
		return m.resealErr
	}
	if _, ok := m.secrets[req.Name]; !ok {
		return errors.New("secret not found")
	}
	return nil
}

func (m *mockSealStoreClient) SealStoreStatus(_ context.Context) (*transport.SealStoreStatusResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statusCalls++
	if m.statusErr != nil {
		return nil, m.statusErr
	}
	names := make([]string, 0, len(m.secrets))
	for name := range m.secrets {
		names = append(names, name)
	}
	return &transport.SealStoreStatusResponse{
		Available:   true,
		SealerID:    "software",
		SecretCount: len(m.secrets),
		SecretNames: names,
	}, nil
}

// resetSealStoreFlags resets all platform-store subcommand flags to their
// default values. This prevents test pollution from Cobra retaining flag state
// across RootCmd.Execute() calls within the same process.
func resetSealStoreFlags() {
	cmds := []*pflag.FlagSet{
		platformStorePutCmd.Flags(),
		platformStoreGetCmd.Flags(),
		platformStoreDeleteCmd.Flags(),
		platformStoreListCmd.Flags(),
		platformStoreResealCmd.Flags(),
		platformStoreStatusCmd.Flags(),
	}
	for _, fs := range cmds {
		fs.VisitAll(func(f *pflag.Flag) {
			f.Changed = false
			_ = f.Value.Set(f.DefValue)
		})
	}
}

// withMockClient injects a mock client factory for the duration of a test
// and restores the original factory on cleanup.
func withMockClient(t *testing.T, mock *mockSealStoreClient) {
	t.Helper()
	original := clientFactory
	clientFactory = func() (SealStoreService, error) {
		return mock, nil
	}
	t.Cleanup(func() {
		clientFactory = original
	})
}

// withFailingClientFactory injects a factory that returns an error.
func withFailingClientFactory(t *testing.T, err error) {
	t.Helper()
	original := clientFactory
	clientFactory = func() (SealStoreService, error) {
		return nil, err
	}
	t.Cleanup(func() {
		clientFactory = original
	})
}

// --- Help and Registration Tests ---

func TestSealStoreCmd_Help(t *testing.T) {
	resetSealStoreFlags()

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("platform-store --help failed: %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"platform-store",
		"sealed secrets",
		"put",
		"get",
		"delete",
		"list",
		"reseal",
		"status",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(strings.ToLower(output), strings.ToLower(expected)) {
			t.Errorf("platform-store help output missing %q", expected)
		}
	}
}

func TestSealStoreCmd_SubcommandRegistration(t *testing.T) {
	subcommands := map[string]bool{
		"put":    false,
		"get":    false,
		"delete": false,
		"list":   false,
		"reseal": false,
		"status": false,
	}

	for _, cmd := range platformStoreCmd.Commands() {
		if _, ok := subcommands[cmd.Name()]; ok {
			subcommands[cmd.Name()] = true
		}
	}

	for name, found := range subcommands {
		if !found {
			t.Errorf("platform-store subcommand %q not registered", name)
		}
	}
}

// --- Error Type Tests ---

func TestSealStoreErrors(t *testing.T) {
	errs := []error{
		ErrSealStoreMissingName,
		ErrSealStoreMissingSource,
		ErrSealStoreMutualExclusive,
		ErrSealStoreFileRead,
		ErrSealStorePutFailed,
		ErrSealStoreGetFailed,
		ErrSealStoreDeleteFailed,
		ErrSealStoreListFailed,
		ErrSealStoreResealFailed,
		ErrSealStoreStatusFailed,
		ErrSealStoreConnectFailed,
		ErrSealStoreOutputWrite,
		ErrSealStoreNoSecretsToReseal,
	}

	for _, err := range errs {
		if err.Error() == "" {
			t.Errorf("platform-store error has empty message: %v", err)
		}
		if !strings.HasPrefix(err.Error(), "platform-store:") {
			t.Errorf("platform-store error missing 'platform-store:' prefix: %v", err)
		}
	}
}

func TestSealStoreError_ErrorFormats(t *testing.T) {
	tests := []struct {
		name     string
		err      *SealStoreError
		expected string
	}{
		{
			name:     "operation only",
			err:      &SealStoreError{Operation: "test"},
			expected: "platform-store: test",
		},
		{
			name:     "operation with message",
			err:      &SealStoreError{Operation: "test", Message: "some message"},
			expected: "platform-store: test: some message",
		},
		{
			name:     "operation with error",
			err:      &SealStoreError{Operation: "test", Err: errors.New("inner")},
			expected: "platform-store: test: inner",
		},
		{
			name:     "operation with message and error",
			err:      &SealStoreError{Operation: "test", Message: "context", Err: errors.New("inner")},
			expected: "platform-store: test: context: inner",
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

func TestSealStoreError_Unwrap(t *testing.T) {
	inner := errors.New("inner error")
	pErr := &SealStoreError{Operation: "test", Err: inner}

	if pErr.Unwrap() != inner {
		t.Errorf("Unwrap() = %v, want %v", pErr.Unwrap(), inner)
	}

	noInner := &SealStoreError{Operation: "test"}
	if noInner.Unwrap() != nil {
		t.Errorf("Unwrap() on error without inner = %v, want nil", noInner.Unwrap())
	}
}

// --- Put Subcommand Tests ---

func TestSealStoreCmd_PutWithValue(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "put", "my-secret", "--value", "s3cret"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("platform-store put failed: %v", err)
	}

	if mock.putCalls != 1 {
		t.Errorf("SealStorePut called %d times, want 1", mock.putCalls)
	}

	stored, ok := mock.secrets["my-secret"]
	if !ok {
		t.Fatal("secret 'my-secret' not stored")
	}
	if string(stored) != "s3cret" {
		t.Errorf("stored secret = %q, want %q", string(stored), "s3cret")
	}

	output := buf.String()
	if !strings.Contains(output, "Stored secret: my-secret") {
		t.Errorf("output missing confirmation, got: %q", output)
	}
}

func TestSealStoreCmd_PutWithFile(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	withMockClient(t, mock)

	// Create a temp file with test content.
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(filePath, []byte("file-secret-content"), 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "put", "from-file", "--file", filePath})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("platform-store put --file failed: %v", err)
	}

	stored, ok := mock.secrets["from-file"]
	if !ok {
		t.Fatal("secret 'from-file' not stored")
	}
	if string(stored) != "file-secret-content" {
		t.Errorf("stored secret = %q, want %q", string(stored), "file-secret-content")
	}
}

func TestSealStoreCmd_PutMissingSource(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "put", "my-secret"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrSealStoreMissingSource) {
		t.Errorf("put without --value or --file: error = %v, want %v", err, ErrSealStoreMissingSource)
	}
}

func TestSealStoreCmd_PutMutuallyExclusive(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{
		"platform-store", "put", "my-secret",
		"--value", "direct",
		"--file", "/some/path",
	})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrSealStoreMutualExclusive) {
		t.Errorf("put with --value and --file: error = %v, want %v", err, ErrSealStoreMutualExclusive)
	}
}

func TestSealStoreCmd_PutFileNotFound(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{
		"platform-store", "put", "my-secret",
		"--file", "/nonexistent/path/secret.txt",
	})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("put with nonexistent file should fail")
	}
	if !errors.Is(err, ErrSealStoreFileRead) {
		t.Errorf("put with nonexistent file: error = %v, want wrapping %v", err, ErrSealStoreFileRead)
	}
}

func TestSealStoreCmd_PutServerError(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.putErr = errors.New("server unavailable")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "put", "my-secret", "--value", "data"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("put with server error should fail")
	}
	if !errors.Is(err, ErrSealStorePutFailed) {
		t.Errorf("put server error: error = %v, want wrapping %v", err, ErrSealStorePutFailed)
	}
}

// --- Get Subcommand Tests ---

func TestSealStoreCmd_GetToStdout(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.secrets["my-secret"] = []byte("retrieved-value")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "get", "my-secret"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("platform-store get failed: %v", err)
	}

	if buf.String() != "retrieved-value" {
		t.Errorf("get output = %q, want %q", buf.String(), "retrieved-value")
	}
}

func TestSealStoreCmd_GetToFile(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.secrets["cert-data"] = []byte("PEM-CERTIFICATE-DATA")
	withMockClient(t, mock)

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "cert.pem")

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "get", "cert-data", "--output", outputPath})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("platform-store get --output failed: %v", err)
	}

	data, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatalf("failed to read output file: %v", readErr)
	}
	if string(data) != "PEM-CERTIFICATE-DATA" {
		t.Errorf("output file content = %q, want %q", string(data), "PEM-CERTIFICATE-DATA")
	}
}

func TestSealStoreCmd_GetNotFound(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "get", "nonexistent"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("get nonexistent secret should fail")
	}
	if !errors.Is(err, ErrSealStoreGetFailed) {
		t.Errorf("get not found: error = %v, want wrapping %v", err, ErrSealStoreGetFailed)
	}
}

func TestSealStoreCmd_GetServerError(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.secrets["exists"] = []byte("data")
	mock.getErr = errors.New("server error")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "get", "exists"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("get with server error should fail")
	}
	if !errors.Is(err, ErrSealStoreGetFailed) {
		t.Errorf("get server error: error = %v, want wrapping %v", err, ErrSealStoreGetFailed)
	}
}

func TestSealStoreCmd_GetOutputWriteError(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.secrets["my-secret"] = []byte("data")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	// Write to a directory that doesn't exist.
	RootCmd.SetArgs([]string{
		"platform-store", "get", "my-secret",
		"--output", "/nonexistent/directory/file.txt",
	})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("get with bad output path should fail")
	}
	if !errors.Is(err, ErrSealStoreOutputWrite) {
		t.Errorf("get output write error: error = %v, want wrapping %v", err, ErrSealStoreOutputWrite)
	}
}

// --- Delete Subcommand Tests ---

func TestSealStoreCmd_Delete(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.secrets["to-delete"] = []byte("data")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "delete", "to-delete"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("platform-store delete failed: %v", err)
	}

	if _, ok := mock.secrets["to-delete"]; ok {
		t.Error("secret 'to-delete' should have been removed")
	}

	output := buf.String()
	if !strings.Contains(output, "Deleted secret: to-delete") {
		t.Errorf("output missing confirmation, got: %q", output)
	}
}

func TestSealStoreCmd_DeleteServerError(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.delErr = errors.New("permission denied")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "delete", "my-secret"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("delete with server error should fail")
	}
	if !errors.Is(err, ErrSealStoreDeleteFailed) {
		t.Errorf("delete server error: error = %v, want wrapping %v", err, ErrSealStoreDeleteFailed)
	}
}

// --- List Subcommand Tests ---

func TestSealStoreCmd_ListWithSecrets(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.secrets["secret-a"] = []byte("a")
	mock.secrets["secret-b"] = []byte("b")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "list"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("platform-store list failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Stored Secrets (2)") {
		t.Errorf("list output missing count header, got: %q", output)
	}
	if !strings.Contains(output, "secret-a") {
		t.Errorf("list output missing 'secret-a', got: %q", output)
	}
	if !strings.Contains(output, "secret-b") {
		t.Errorf("list output missing 'secret-b', got: %q", output)
	}
}

func TestSealStoreCmd_ListEmpty(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "list"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("platform-store list (empty) failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No secrets stored") {
		t.Errorf("empty list output missing message, got: %q", output)
	}
}

func TestSealStoreCmd_ListServerError(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.listErr = errors.New("connection refused")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "list"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("list with server error should fail")
	}
	if !errors.Is(err, ErrSealStoreListFailed) {
		t.Errorf("list server error: error = %v, want wrapping %v", err, ErrSealStoreListFailed)
	}
}

// --- Reseal Subcommand Tests ---

func TestSealStoreCmd_ResealSingle(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.secrets["my-secret"] = []byte("data")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "reseal", "my-secret"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("platform-store reseal failed: %v", err)
	}

	if mock.resealCalls != 1 {
		t.Errorf("SealStoreReseal called %d times, want 1", mock.resealCalls)
	}

	output := buf.String()
	if !strings.Contains(output, "Resealed: my-secret") {
		t.Errorf("reseal output missing confirmation, got: %q", output)
	}
}

func TestSealStoreCmd_ResealAll(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.secrets["secret-1"] = []byte("a")
	mock.secrets["secret-2"] = []byte("b")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "reseal", "--all"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("platform-store reseal --all failed: %v", err)
	}

	if mock.resealCalls != 2 {
		t.Errorf("SealStoreReseal called %d times, want 2", mock.resealCalls)
	}

	output := buf.String()
	if !strings.Contains(output, "Resealed 2 secret(s)") {
		t.Errorf("reseal --all output missing count, got: %q", output)
	}
}

func TestSealStoreCmd_ResealMissingName(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "reseal"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrSealStoreMissingName) {
		t.Errorf("reseal without name or --all: error = %v, want %v", err, ErrSealStoreMissingName)
	}
}

func TestSealStoreCmd_ResealAllEmpty(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "reseal", "--all"})

	err := RootCmd.Execute()
	if !errors.Is(err, ErrSealStoreNoSecretsToReseal) {
		t.Errorf("reseal --all with no secrets: error = %v, want %v", err, ErrSealStoreNoSecretsToReseal)
	}
}

func TestSealStoreCmd_ResealServerError(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.secrets["my-secret"] = []byte("data")
	mock.resealErr = errors.New("sealer unavailable")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "reseal", "my-secret"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("reseal with server error should fail")
	}
	if !errors.Is(err, ErrSealStoreResealFailed) {
		t.Errorf("reseal server error: error = %v, want wrapping %v", err, ErrSealStoreResealFailed)
	}
}

func TestSealStoreCmd_ResealAllListError(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.listErr = errors.New("list failed")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "reseal", "--all"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("reseal --all with list error should fail")
	}
	if !errors.Is(err, ErrSealStoreListFailed) {
		t.Errorf("reseal --all list error: error = %v, want wrapping %v", err, ErrSealStoreListFailed)
	}
}

// --- Status Subcommand Tests ---

func TestSealStoreCmd_Status(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.secrets["secret-a"] = []byte("a")
	mock.secrets["secret-b"] = []byte("b")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "status"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("platform-store status failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Platform Store Status") {
		t.Errorf("status output missing header, got: %q", output)
	}
	if !strings.Contains(output, "Available:     true") {
		t.Errorf("status output missing Available, got: %q", output)
	}
	if !strings.Contains(output, "Sealer:        software") {
		t.Errorf("status output missing Sealer, got: %q", output)
	}
	if !strings.Contains(output, "Secret Count:  2") {
		t.Errorf("status output missing Secret Count, got: %q", output)
	}
}

func TestSealStoreCmd_StatusServerError(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	mock.statusErr = errors.New("server down")
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "status"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("status with server error should fail")
	}
	if !errors.Is(err, ErrSealStoreStatusFailed) {
		t.Errorf("status server error: error = %v, want wrapping %v", err, ErrSealStoreStatusFailed)
	}
}

func TestSealStoreCmd_StatusEmpty(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	withMockClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "status"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("platform-store status (empty) failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Secret Count:  0") {
		t.Errorf("empty status output missing zero count, got: %q", output)
	}
}

// --- Connection Error Tests ---

func TestSealStoreCmd_ConnectError(t *testing.T) {
	resetSealStoreFlags()
	withFailingClientFactory(t, errors.New("no server"))

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "list"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("list with connection error should fail")
	}
	if !errors.Is(err, ErrSealStoreConnectFailed) {
		t.Errorf("connect error: error = %v, want wrapping %v", err, ErrSealStoreConnectFailed)
	}
}

func TestSealStoreCmd_ConnectErrorOnPut(t *testing.T) {
	resetSealStoreFlags()
	withFailingClientFactory(t, errors.New("no server"))

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "put", "name", "--value", "val"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("put with connection error should fail")
	}
	if !errors.Is(err, ErrSealStoreConnectFailed) {
		t.Errorf("connect error on put: error = %v, want wrapping %v", err, ErrSealStoreConnectFailed)
	}
}

// --- PutAndGet Roundtrip Test ---

func TestSealStoreCmd_PutAndGetRoundtrip(t *testing.T) {
	resetSealStoreFlags()
	mock := newMockSealStoreClient()
	withMockClient(t, mock)

	// Put a secret.
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "put", "roundtrip", "--value", "round-trip-value"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("put failed: %v", err)
	}

	// Get the secret back.
	resetSealStoreFlags()
	buf.Reset()
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"platform-store", "get", "roundtrip"})

	err = RootCmd.Execute()
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}

	if buf.String() != "round-trip-value" {
		t.Errorf("roundtrip value = %q, want %q", buf.String(), "round-trip-value")
	}
}

// --- Delete Alias Test ---

func TestSealStoreCmd_DeleteAlias(t *testing.T) {
	// Verify the "rm" alias is registered.
	found := false
	for _, alias := range platformStoreDeleteCmd.Aliases {
		if alias == "rm" {
			found = true
			break
		}
	}
	if !found {
		t.Error("platform-store delete missing 'rm' alias")
	}
}

// --- List Alias Test ---

func TestSealStoreCmd_ListAlias(t *testing.T) {
	found := false
	for _, alias := range platformStoreListCmd.Aliases {
		if alias == "ls" {
			found = true
			break
		}
	}
	if !found {
		t.Error("platform-store list missing 'ls' alias")
	}
}
