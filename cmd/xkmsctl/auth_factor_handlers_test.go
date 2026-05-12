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

// auth_factor_handlers_test.go covers the xkmsctl "auth login" and
// "auth factor" canonical surface wired against the qrdb SDK
// user-side AuthFactor service (M14, UserAuthFactorClient).
package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// ---------------------------------------------------------------------------
// Mock UserAuthFactorClient
// ---------------------------------------------------------------------------

// mockXKMSUserAuthFactorClient implements
// qrdbtransport.UserAuthFactorClient with a process-local in-memory
// store. Tests inject it via SetUserAuthFactorClientFactory.
type mockXKMSUserAuthFactorClient struct {
	mu      sync.Mutex
	nextID  int
	factors map[string]*qrdbtransport.AuthFactorRecord
}

func newMockXKMSUserAuthFactorClient() *mockXKMSUserAuthFactorClient {
	return &mockXKMSUserAuthFactorClient{
		factors: make(map[string]*qrdbtransport.AuthFactorRecord),
	}
}

// AddAuthFactor stores a new factor record.
func (m *mockXKMSUserAuthFactorClient) AddAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorAddRequest) (*qrdbtransport.AuthFactorAddResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	id := "factor-mock-" + xkmsIntToString(m.nextID)
	rec := &qrdbtransport.AuthFactorRecord{
		ID:           id,
		UserID:       req.UserID,
		Type:         req.Type,
		Label:        req.Label,
		Credential:   append([]byte(nil), req.Credential...),
		Metadata:     xkmsCopyMetadata(req.Metadata),
		RegisteredAt: time.Date(2026, 4, 25, 0, 0, 0, 0, time.UTC),
		CreatedBy:    req.CreatedBy,
	}
	m.factors[id] = rec
	return &qrdbtransport.AuthFactorAddResponse{Factor: *rec}, nil
}

// ListAuthFactors returns every factor for a user.
func (m *mockXKMSUserAuthFactorClient) ListAuthFactors(_ context.Context, req *qrdbtransport.AuthFactorListRequest) (*qrdbtransport.AuthFactorListResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]qrdbtransport.AuthFactorRecord, 0)
	for _, f := range m.factors {
		if f.UserID == req.UserID {
			out = append(out, *f)
		}
	}
	return &qrdbtransport.AuthFactorListResponse{Factors: out, Total: len(out)}, nil
}

// GetAuthFactor returns a factor by id.
func (m *mockXKMSUserAuthFactorClient) GetAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorGetRequest) (*qrdbtransport.AuthFactorGetResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.factors[req.FactorID]
	if !ok {
		return nil, errors.New("factor not found: " + req.FactorID)
	}
	return &qrdbtransport.AuthFactorGetResponse{Factor: *rec}, nil
}

// RemoveAuthFactor soft-deletes a factor.
func (m *mockXKMSUserAuthFactorClient) RemoveAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorRemoveRequest) (*qrdbtransport.AuthFactorRemoveResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.factors[req.FactorID]
	if !ok {
		return nil, errors.New("factor not found: " + req.FactorID)
	}
	now := time.Date(2026, 4, 25, 1, 0, 0, 0, time.UTC)
	rec.RevokedAt = &now
	return &qrdbtransport.AuthFactorRemoveResponse{Status: "revoked"}, nil
}

// RotateAuthFactor revokes the old factor and adds a new one.
func (m *mockXKMSUserAuthFactorClient) RotateAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorRotateRequest) (*qrdbtransport.AuthFactorRotateResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.factors[req.OldFactorID]
	if !ok {
		return nil, errors.New("factor not found: " + req.OldFactorID)
	}
	now := time.Date(2026, 4, 25, 2, 0, 0, 0, time.UTC)
	old.RevokedAt = &now
	userID := req.NewFactor.UserID
	if userID == 0 {
		userID = old.UserID
	}
	m.nextID++
	id := "factor-mock-" + xkmsIntToString(m.nextID)
	rec := &qrdbtransport.AuthFactorRecord{
		ID:           id,
		UserID:       userID,
		Type:         req.NewFactor.Type,
		Label:        req.NewFactor.Label,
		Credential:   append([]byte(nil), req.NewFactor.Credential...),
		Metadata:     xkmsCopyMetadata(req.NewFactor.Metadata),
		RegisteredAt: time.Date(2026, 4, 25, 2, 0, 0, 0, time.UTC),
		CreatedBy:    req.NewFactor.CreatedBy,
	}
	m.factors[id] = rec
	return &qrdbtransport.AuthFactorRotateResponse{NewFactor: *rec}, nil
}

// RelabelAuthFactor renames a factor.
func (m *mockXKMSUserAuthFactorClient) RelabelAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorRelabelRequest) (*qrdbtransport.AuthFactorRelabelResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.factors[req.FactorID]
	if !ok {
		return nil, errors.New("factor not found: " + req.FactorID)
	}
	rec.Label = req.Label
	return &qrdbtransport.AuthFactorRelabelResponse{Factor: *rec}, nil
}

// LoginAuthFactor resolves a (Type, LookupKey) tuple to a user record.
func (m *mockXKMSUserAuthFactorClient) LoginAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorLoginRequest) (*qrdbtransport.AuthFactorLoginResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range m.factors {
		if f.Type != req.Type {
			continue
		}
		if string(f.Credential) != string(req.LookupKey) {
			continue
		}
		if f.RevokedAt != nil {
			return nil, errors.New("factor revoked")
		}
		return &qrdbtransport.AuthFactorLoginResponse{
			UserID:   f.UserID,
			Username: "user-" + xkmsIntToString(int(f.UserID)),
			Active:   true,
			Factor:   *f,
		}, nil
	}
	return nil, errors.New("factor not found for lookup key")
}

// xkmsCopyMetadata returns a defensive copy of a string-string map.
func xkmsCopyMetadata(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// xkmsIntToString returns a base-10 representation of an int. Avoids
// pulling strconv just for the mock id minting.
func xkmsIntToString(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

// installMockFactory swaps in a process-local mock client for the
// duration of the calling test and returns the mock plus a cleanup
// closure. The cleanup closure restores the previous factory.
func installMockFactory(t *testing.T) (*mockXKMSUserAuthFactorClient, func()) {
	t.Helper()
	mock := newMockXKMSUserAuthFactorClient()
	restore := SetUserAuthFactorClientFactory(func(_ context.Context) (qrdbtransport.UserAuthFactorClient, func() error, error) {
		return mock, func() error { return nil }, nil
	})
	return mock, restore
}

// runAuthCmd executes the xkmsctl rootCmd with the supplied args and
// captures os.Stdout output. Cobra retains parsed flag values across
// Execute calls when commands are shared globally - runAuthCmd resets
// every flag on the auth subtree to its registered default before
// invocation so each test sees a clean slate.
func runAuthCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetAuthFlags(t)
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	rootCmd.SetArgs(args)
	err := rootCmd.Execute()

	_ = w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	rootCmd.SetArgs([]string{})
	return buf.String(), err
}

// resetAuthFlags resets every flag on the "auth" subtree to its
// registered default. cobra otherwise carries flag state across
// Execute calls when commands are shared globally.
func resetAuthFlags(t *testing.T) {
	t.Helper()
	authCmd, _, err := rootCmd.Find([]string{"auth"})
	if err != nil {
		t.Fatalf("locate auth subcommand: %v", err)
	}
	resetCmdFlagsRecursive(authCmd)
}

// resetCmdFlagsRecursive resets every local flag on cmd and all its
// descendants to its registered default value.
func resetCmdFlagsRecursive(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	for _, child := range cmd.Commands() {
		resetCmdFlagsRecursive(child)
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestXKMSAuthFactorAdd_success exercises the canonical add flow.
func TestXKMSAuthFactorAdd_success(t *testing.T) {
	_, restore := installMockFactory(t)
	defer restore()

	out, err := runAuthCmd(t,
		"auth", "factor", "add",
		"--user", "42",
		"--type", "fido2",
		"--label", "yk-work",
		"--credential-hex", "deadbeef",
	)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if !strings.Contains(out, "yk-work") {
		t.Fatalf("expected label in output, got: %q", out)
	}
}

// TestXKMSAuthFactorAdd_invalidUserID asserts non-numeric --user is
// rejected.
func TestXKMSAuthFactorAdd_invalidUserID(t *testing.T) {
	_, restore := installMockFactory(t)
	defer restore()

	_, err := runAuthCmd(t,
		"auth", "factor", "add",
		"--user", "alice",
		"--type", "fido2",
		"--label", "x",
		"--credential-hex", "00",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var iue *InvalidUserIDError
	if !errors.As(err, &iue) {
		t.Fatalf("want *InvalidUserIDError, got %T: %v", err, err)
	}
}

// TestXKMSAuthFactorList_success exercises the canonical list flow.
func TestXKMSAuthFactorList_success(t *testing.T) {
	mock, restore := installMockFactory(t)
	defer restore()

	mock.factors["seed-1"] = &qrdbtransport.AuthFactorRecord{
		ID:           "seed-1",
		UserID:       7,
		Type:         "mtls",
		Label:        "alice-mtls",
		Credential:   []byte("creda"),
		RegisteredAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	out, err := runAuthCmd(t, "auth", "factor", "list", "--user", "7")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "seed-1") {
		t.Fatalf("expected factor id in output, got: %q", out)
	}
}

// TestXKMSAuthFactorList_missingUser asserts list fails fast when
// --user is not supplied.
func TestXKMSAuthFactorList_missingUser(t *testing.T) {
	_, restore := installMockFactory(t)
	defer restore()

	_, err := runAuthCmd(t, "auth", "factor", "list")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var mu *MissingUserError
	if !errors.As(err, &mu) {
		t.Fatalf("want *MissingUserError, got %T: %v", err, err)
	}
}

// TestXKMSAuthFactorRelabel_success is the headline test: the M14
// RelabelAuthFactor RPC must be invoked and succeed.
func TestXKMSAuthFactorRelabel_success(t *testing.T) {
	mock, restore := installMockFactory(t)
	defer restore()

	mock.factors["abc"] = &qrdbtransport.AuthFactorRecord{
		ID:           "abc",
		UserID:       1,
		Type:         "mtls",
		Label:        "old-label",
		Credential:   []byte("k"),
		RegisteredAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	out, err := runAuthCmd(t, "auth", "factor", "relabel", "abc", "--label", "new-label")
	if err != nil {
		t.Fatalf("relabel: %v", err)
	}
	if !strings.Contains(out, "new-label") {
		t.Fatalf("expected new label in output, got: %q", out)
	}
	if got := mock.factors["abc"].Label; got != "new-label" {
		t.Fatalf("mock factor label = %q, want new-label", got)
	}
}

// TestXKMSAuthFactorRelabel_missingFactorID asserts the handler
// rejects a missing positional argument.
func TestXKMSAuthFactorRelabel_missingFactorID(t *testing.T) {
	_, restore := installMockFactory(t)
	defer restore()

	_, err := runAuthCmd(t, "auth", "factor", "relabel", "--label", "x")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var mfid *MissingFactorIDError
	if !errors.As(err, &mfid) {
		t.Fatalf("want *MissingFactorIDError, got %T: %v", err, err)
	}
}

// TestXKMSAuthFactorRelabel_missingLabel asserts the handler rejects a
// missing --label flag.
func TestXKMSAuthFactorRelabel_missingLabel(t *testing.T) {
	_, restore := installMockFactory(t)
	defer restore()

	_, err := runAuthCmd(t, "auth", "factor", "relabel", "abc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ml *MissingLabelError
	if !errors.As(err, &ml) {
		t.Fatalf("want *MissingLabelError, got %T: %v", err, err)
	}
}

// TestXKMSAuthFactorRemove_success exercises the canonical remove flow.
func TestXKMSAuthFactorRemove_success(t *testing.T) {
	mock, restore := installMockFactory(t)
	defer restore()

	mock.factors["rm-1"] = &qrdbtransport.AuthFactorRecord{
		ID:           "rm-1",
		UserID:       1,
		Type:         "mtls",
		Credential:   []byte("k"),
		RegisteredAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	if _, err := runAuthCmd(t, "auth", "factor", "remove", "rm-1"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if mock.factors["rm-1"].RevokedAt == nil {
		t.Fatal("expected RevokedAt to be set")
	}
}

// TestXKMSAuthFactorRotate_success exercises the canonical rotate flow.
func TestXKMSAuthFactorRotate_success(t *testing.T) {
	mock, restore := installMockFactory(t)
	defer restore()

	mock.factors["old"] = &qrdbtransport.AuthFactorRecord{
		ID:           "old",
		UserID:       9,
		Type:         "fido2",
		Credential:   []byte("oldcred"),
		RegisteredAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	out, err := runAuthCmd(t,
		"auth", "factor", "rotate", "old",
		"--type", "fido2",
		"--label", "rotated",
		"--credential-hex", "cafebabe",
	)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !strings.Contains(out, "Old factor revoked") {
		t.Fatalf("expected rotation banner, got: %q", out)
	}
	if mock.factors["old"].RevokedAt == nil {
		t.Fatal("expected old factor RevokedAt to be set")
	}
}

// TestXKMSAuthLogin_fido2_success exercises the M14 LoginAuthFactor
// RPC for fido2.
func TestXKMSAuthLogin_fido2_success(t *testing.T) {
	mock, restore := installMockFactory(t)
	defer restore()

	mock.factors["login-1"] = &qrdbtransport.AuthFactorRecord{
		ID:           "login-1",
		UserID:       77,
		Type:         "fido2",
		Label:        "yk-home",
		Credential:   []byte{0xde, 0xad, 0xbe, 0xef},
		RegisteredAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	out, err := runAuthCmd(t,
		"auth", "login",
		"--method", "fido2",
		"--credential-hex", "deadbeef",
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !strings.Contains(out, "User ID:   77") {
		t.Fatalf("expected resolved user id 77 in output, got: %q", out)
	}
}

// TestXKMSAuthLogin_invalidMethod asserts the handler rejects a method
// outside the canonical set.
func TestXKMSAuthLogin_invalidMethod(t *testing.T) {
	_, restore := installMockFactory(t)
	defer restore()

	_, err := runAuthCmd(t,
		"auth", "login",
		"--method", "smartcard",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var iam *InvalidAuthMethodError
	if !errors.As(err, &iam) {
		t.Fatalf("want *InvalidAuthMethodError, got %T: %v", err, err)
	}
}

// TestXKMSAuthFactorDefaultFactory verifies the default factory
// returns the canonical missing-client error so production binaries
// surface a clear operator-facing message rather than a stack trace.
func TestXKMSAuthFactorDefaultFactory(t *testing.T) {
	prev := userAuthFactorClientFactory
	userAuthFactorClientFactory = defaultUserAuthFactorClientFactory
	defer func() { userAuthFactorClientFactory = prev }()

	cl, closeFn, err := userAuthFactorClient(context.Background())
	if cl != nil {
		t.Fatalf("expected nil client, got %T", cl)
	}
	if closeFn != nil {
		t.Fatal("expected nil closeFn")
	}
	var mc *AuthFactorMissingClientError
	if !errors.As(err, &mc) {
		t.Fatalf("want *AuthFactorMissingClientError, got %T: %v", err, err)
	}
}
