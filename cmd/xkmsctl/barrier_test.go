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

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockBarrierClient is a mock client for testing barrier operations.
type mockBarrierClient struct {
	mockBackendsClient

	// Barrier operation results
	initErr            error
	unsealErr          error
	sealBarrierErr     error
	statusResp         *transport.BarrierStatusResponse
	statusErr          error
	initShamirResp     *transport.BarrierInitializeShamirResponse
	initShamirErr      error
	unsealShareResp    *transport.BarrierUnsealShareResponse
	unsealShareErr     error
	unsealSharesErr    error
	connectBarrierErr  error
	closeBarrierCalled bool
	closeBarrierErr    error
}

func (m *mockBarrierClient) Connect(ctx context.Context) error {
	return m.connectBarrierErr
}

func (m *mockBarrierClient) Close() error {
	m.closeBarrierCalled = true
	return m.closeBarrierErr
}

func (m *mockBarrierClient) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	return m.initErr
}

func (m *mockBarrierClient) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	return m.unsealErr
}

func (m *mockBarrierClient) BarrierSeal(ctx context.Context) error {
	return m.sealBarrierErr
}

func (m *mockBarrierClient) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	return m.statusResp, m.statusErr
}

func (m *mockBarrierClient) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	return m.initShamirResp, m.initShamirErr
}

func (m *mockBarrierClient) BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	return m.unsealShareResp, m.unsealShareErr
}

func (m *mockBarrierClient) BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error {
	return m.unsealSharesErr
}

// newBarrierConfig creates a Config with a mock barrier client injected.
func newBarrierConfig(mock *mockBarrierClient) *Config {
	return &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mock, nil
		},
	}
}

// newBarrierErrorConfig creates a Config that fails on client creation.
func newBarrierErrorConfig() *Config {
	return &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("client creation failed")
		},
	}
}

// --- Command existence and properties ---

func TestBarrierCmd_Exists(t *testing.T) {
	if barrierCmd == nil {
		t.Fatal("barrierCmd should not be nil")
	}
}

func TestBarrierCmd_Properties(t *testing.T) {
	if barrierCmd.Use != "barrier" {
		t.Errorf("barrierCmd.Use = %q, want %q", barrierCmd.Use, "barrier")
	}
	if barrierCmd.Short == "" {
		t.Error("barrierCmd.Short should not be empty")
	}
}

func TestBarrierCmd_HasSubcommands(t *testing.T) {
	expectedCmds := map[string]bool{
		"init":       false,
		"unseal":     false,
		"seal":       false,
		"status":     false,
		"shares":     false,
		"rekey":      false,
		"root-token": false,
		"recovery":   false,
	}

	for _, cmd := range barrierCmd.Commands() {
		if _, ok := expectedCmds[cmd.Name()]; ok {
			expectedCmds[cmd.Name()] = true
		}
	}

	for name, found := range expectedCmds {
		if !found {
			t.Errorf("expected subcommand %q not found in barrierCmd", name)
		}
	}
}

func TestBarrierSharesCmd_HasSubcommands(t *testing.T) {
	expectedCmds := map[string]bool{
		"list":   false,
		"verify": false,
		"delete": false,
	}

	for _, cmd := range barrierSharesCmd.Commands() {
		if _, ok := expectedCmds[cmd.Name()]; ok {
			expectedCmds[cmd.Name()] = true
		}
	}

	for name, found := range expectedCmds {
		if !found {
			t.Errorf("expected subcommand %q not found in barrierSharesCmd", name)
		}
	}
}

func TestBarrierRecoveryCmd_HasSubcommands(t *testing.T) {
	expectedCmds := map[string]bool{
		"generate": false,
		"recover":  false,
		"delete":   false,
	}

	for _, cmd := range barrierRecoveryCmd.Commands() {
		if _, ok := expectedCmds[cmd.Name()]; ok {
			expectedCmds[cmd.Name()] = true
		}
	}

	for name, found := range expectedCmds {
		if !found {
			t.Errorf("expected subcommand %q not found in barrierRecoveryCmd", name)
		}
	}
}

func TestBarrierCmd_RegisteredInRoot(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "barrier" {
			found = true
			break
		}
	}
	if !found {
		t.Error("barrierCmd should be registered as a subcommand of rootCmd")
	}
}

// --- barrierInit ---

func TestBarrierInit_Success(t *testing.T) {
	mock := &mockBarrierClient{}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierInit(cfg, printer, "my-secret")

	output := buf.String()
	if !strings.Contains(output, "success") {
		t.Error("barrierInit should report success")
	}
}

func TestBarrierInit_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		initErr: errors.New("init failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierInit(cfg, printer, "my-secret")
	// Should not panic
}

func TestBarrierInit_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierInit(cfg, printer, "secret")
	// Should not panic
}

func TestBarrierInit_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		connectBarrierErr: errors.New("connect failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierInit(cfg, printer, "secret")
	// Should not panic
}

// --- barrierInitShamir ---

func TestBarrierInitShamir_Success(t *testing.T) {
	mock := &mockBarrierClient{
		initShamirResp: &transport.BarrierInitializeShamirResponse{
			Shares:      []string{"share-1", "share-2", "share-3"},
			Threshold:   2,
			TotalShares: 3,
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierInitShamir(cfg, printer, "my-secret", 2, 3)

	output := buf.String()
	if !strings.Contains(output, "share-1") {
		t.Error("barrierInitShamir should output shares")
	}
	if !strings.Contains(output, "threshold") {
		t.Error("barrierInitShamir should output threshold")
	}
}

func TestBarrierInitShamir_TextFormat(t *testing.T) {
	mock := &mockBarrierClient{
		initShamirResp: &transport.BarrierInitializeShamirResponse{
			Shares:      []string{"aaa", "bbb", "ccc"},
			Threshold:   2,
			TotalShares: 3,
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	barrierInitShamir(cfg, printer, "secret", 2, 3)

	output := buf.String()
	if !strings.Contains(output, "Shamir Secret Sharing Initialized") {
		t.Error("text output should contain initialization header")
	}
	if !strings.Contains(output, "Share 1: aaa") {
		t.Error("text output should contain numbered shares")
	}
	if !strings.Contains(output, "WARNING") {
		t.Error("text output should contain a warning")
	}
}

func TestBarrierInitShamir_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		initShamirErr: errors.New("shamir init failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierInitShamir(cfg, printer, "secret", 2, 3)
}

func TestBarrierInitShamir_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierInitShamir(cfg, printer, "secret", 2, 3)
}

// --- barrierUnsealWithSecret ---

func TestBarrierUnsealWithSecret_Success(t *testing.T) {
	mock := &mockBarrierClient{}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierUnsealWithSecret(cfg, printer, "my-secret")

	output := buf.String()
	if !strings.Contains(output, "success") {
		t.Error("barrierUnsealWithSecret should report success")
	}
}

func TestBarrierUnsealWithSecret_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		unsealErr: errors.New("unseal failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierUnsealWithSecret(cfg, printer, "secret")
}

func TestBarrierUnsealWithSecret_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierUnsealWithSecret(cfg, printer, "secret")
}

// --- barrierUnsealWithShare ---

func TestBarrierUnsealWithShare_Incomplete(t *testing.T) {
	mock := &mockBarrierClient{
		unsealShareResp: &transport.BarrierUnsealShareResponse{
			Required:  3,
			Submitted: 1,
			Complete:  false,
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierUnsealWithShare(cfg, printer, "share-1")

	output := buf.String()
	if !strings.Contains(output, "\"complete\": false") {
		t.Error("incomplete unseal should show complete: false")
	}
	if !strings.Contains(output, "\"submitted\": 1") {
		t.Error("incomplete unseal should show submitted count")
	}
}

func TestBarrierUnsealWithShare_Complete(t *testing.T) {
	mock := &mockBarrierClient{
		unsealShareResp: &transport.BarrierUnsealShareResponse{
			Required:  2,
			Submitted: 2,
			Complete:  true,
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	barrierUnsealWithShare(cfg, printer, "share-2")

	output := buf.String()
	if !strings.Contains(output, "unsealed successfully") {
		t.Error("complete unseal should report success")
	}
}

func TestBarrierUnsealWithShare_TextIncomplete(t *testing.T) {
	mock := &mockBarrierClient{
		unsealShareResp: &transport.BarrierUnsealShareResponse{
			Required:  3,
			Submitted: 2,
			Complete:  false,
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	barrierUnsealWithShare(cfg, printer, "share-x")

	output := buf.String()
	if !strings.Contains(output, "need 1 more") {
		t.Error("text incomplete should show how many more shares are needed")
	}
}

func TestBarrierUnsealWithShare_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		unsealShareErr: errors.New("share rejected"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierUnsealWithShare(cfg, printer, "bad-share")
}

func TestBarrierUnsealWithShare_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierUnsealWithShare(cfg, printer, "share")
}

// --- barrierUnsealWithShares ---

func TestBarrierUnsealWithShares_Success(t *testing.T) {
	mock := &mockBarrierClient{}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierUnsealWithShares(cfg, printer, []string{"share-1", "share-2", "share-3"})

	output := buf.String()
	if !strings.Contains(output, "success") {
		t.Error("barrierUnsealWithShares should report success")
	}
}

func TestBarrierUnsealWithShares_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		unsealSharesErr: errors.New("batch unseal failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierUnsealWithShares(cfg, printer, []string{"share-1", "share-2"})
}

func TestBarrierUnsealWithShares_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierUnsealWithShares(cfg, printer, []string{"share-1"})
}

// --- barrierSeal ---

func TestBarrierSeal_Success(t *testing.T) {
	mock := &mockBarrierClient{}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSeal(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "success") {
		t.Error("barrierSeal should report success")
	}
}

func TestBarrierSeal_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		sealBarrierErr: errors.New("seal failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSeal(cfg, printer)
}

func TestBarrierSeal_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSeal(cfg, printer)
}

// --- barrierStatus ---

func TestBarrierStatus_Unsealed(t *testing.T) {
	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:         false,
			Strategy:       "password",
			HardwareBacked: false,
			InitializedAt:  "2025-01-15T10:30:00Z",
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierStatus(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "\"sealed\": false") {
		t.Error("status should show sealed: false")
	}
	if !strings.Contains(output, "password") {
		t.Error("status should show the strategy")
	}
	if !strings.Contains(output, "initialized_at") {
		t.Error("status should show initialized_at when present")
	}
}

func TestBarrierStatus_Sealed(t *testing.T) {
	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:         true,
			Strategy:       "shamir",
			HardwareBacked: true,
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	barrierStatus(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "sealed") {
		t.Error("text status should show 'sealed' state")
	}
	if !strings.Contains(output, "shamir") {
		t.Error("text status should show strategy")
	}
	if !strings.Contains(output, "true") {
		t.Error("text status should show hardware_backed: true")
	}
}

func TestBarrierStatus_UnsealedText(t *testing.T) {
	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:         false,
			Strategy:       "password",
			HardwareBacked: false,
			InitializedAt:  "2025-06-01T00:00:00Z",
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	barrierStatus(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "unsealed") {
		t.Error("text status should show 'unsealed' when not sealed")
	}
	if !strings.Contains(output, "Initialized At") {
		t.Error("text status should show initialized_at")
	}
}

func TestBarrierStatus_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		statusErr: errors.New("status failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierStatus(cfg, printer)
}

func TestBarrierStatus_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierStatus(cfg, printer)
}

// --- barrierRekey ---

func TestBarrierRekey_Success(t *testing.T) {
	mock := &mockBarrierClient{
		initShamirResp: &transport.BarrierInitializeShamirResponse{
			Shares:      []string{"new-1", "new-2", "new-3", "new-4", "new-5"},
			Threshold:   3,
			TotalShares: 5,
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRekey(cfg, printer, 3, 5)

	output := buf.String()
	if !strings.Contains(output, "new-1") {
		t.Error("rekey should output new shares")
	}
	if !strings.Contains(output, "\"threshold\": 3") {
		t.Error("rekey should output new threshold")
	}
}

func TestBarrierRekey_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		initShamirErr: errors.New("rekey failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRekey(cfg, printer, 3, 5)
}

func TestBarrierRekey_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRekey(cfg, printer, 3, 5)
}

// --- barrierRootToken ---

func TestBarrierRootToken_Success(t *testing.T) {
	mock := &mockBarrierClient{}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRootToken(cfg, printer, []string{"share-1", "share-2", "share-3"})

	output := buf.String()
	if !strings.Contains(output, "success") {
		t.Error("root token generation should report success")
	}
}

func TestBarrierRootToken_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		unsealSharesErr: errors.New("root token failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRootToken(cfg, printer, []string{"share-1", "share-2"})
}

func TestBarrierRootToken_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRootToken(cfg, printer, []string{"share-1"})
}

// --- barrierSharesList ---

func TestBarrierSharesList_Success(t *testing.T) {
	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:   false,
			Strategy: "shamir",
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesList(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "shamir") {
		t.Error("shares list should show strategy")
	}
}

func TestBarrierSharesList_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		statusErr: errors.New("status failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesList(cfg, printer)
}

func TestBarrierSharesList_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesList(cfg, printer)
}

// --- barrierSharesVerify ---

func TestBarrierSharesVerify_Success(t *testing.T) {
	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:   false,
			Strategy: "shamir",
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesVerify(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "success") {
		t.Error("shares verify should report success for shamir strategy")
	}
}

func TestBarrierSharesVerify_NotShamir(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:   false,
			Strategy: "password",
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesVerify(cfg, printer)
	// Should error with ErrBarrierNotShamir
}

func TestBarrierSharesVerify_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		statusErr: errors.New("verify failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesVerify(cfg, printer)
}

func TestBarrierSharesVerify_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesVerify(cfg, printer)
}

// --- barrierSharesDelete ---

func TestBarrierSharesDelete_Success(t *testing.T) {
	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:   false,
			Strategy: "shamir",
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesDelete(cfg, printer, "2")

	output := buf.String()
	if !strings.Contains(output, "deleted") {
		t.Error("shares delete should report deletion")
	}
}

func TestBarrierSharesDelete_InvalidIndex(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:   false,
			Strategy: "shamir",
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesDelete(cfg, printer, "not-a-number")
	// Should error with ErrBarrierInvalidShareIndex
}

func TestBarrierSharesDelete_NotShamir(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:   false,
			Strategy: "password",
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesDelete(cfg, printer, "0")
}

func TestBarrierSharesDelete_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesDelete(cfg, printer, "0")
}

// --- barrierSharesDeleteAll ---

func TestBarrierSharesDeleteAll_Success(t *testing.T) {
	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:   false,
			Strategy: "shamir",
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesDeleteAll(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "deleted") {
		t.Error("shares delete all should report deletion")
	}
}

func TestBarrierSharesDeleteAll_NotShamir(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:   false,
			Strategy: "password",
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesDeleteAll(cfg, printer)
}

func TestBarrierSharesDeleteAll_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		statusErr: errors.New("status failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesDeleteAll(cfg, printer)
}

func TestBarrierSharesDeleteAll_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSharesDeleteAll(cfg, printer)
}

// --- barrierRecoveryGenerate ---

func TestBarrierRecoveryGenerate_Success(t *testing.T) {
	mock := &mockBarrierClient{
		initShamirResp: &transport.BarrierInitializeShamirResponse{
			Shares:      []string{"rk-1", "rk-2", "rk-3"},
			Threshold:   2,
			TotalShares: 3,
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRecoveryGenerate(cfg, printer, 2, 3)

	output := buf.String()
	if !strings.Contains(output, "rk-1") {
		t.Error("recovery generate should output keys")
	}
	if !strings.Contains(output, "recovery_keys") {
		t.Error("recovery generate should have 'recovery_keys' field in JSON")
	}
}

func TestBarrierRecoveryGenerate_TextFormat(t *testing.T) {
	mock := &mockBarrierClient{
		initShamirResp: &transport.BarrierInitializeShamirResponse{
			Shares:      []string{"rk-a", "rk-b"},
			Threshold:   1,
			TotalShares: 2,
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	barrierRecoveryGenerate(cfg, printer, 1, 2)

	output := buf.String()
	if !strings.Contains(output, "Recovery Keys Generated") {
		t.Error("text output should contain header")
	}
	if !strings.Contains(output, "Key 1: rk-a") {
		t.Error("text output should contain numbered keys")
	}
}

func TestBarrierRecoveryGenerate_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		initShamirErr: errors.New("generate failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRecoveryGenerate(cfg, printer, 2, 3)
}

func TestBarrierRecoveryGenerate_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRecoveryGenerate(cfg, printer, 2, 3)
}

// --- barrierRecoveryRecover ---

func TestBarrierRecoveryRecover_Success(t *testing.T) {
	mock := &mockBarrierClient{}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRecoveryRecover(cfg, printer, []string{"rk-1", "rk-2"})

	output := buf.String()
	if !strings.Contains(output, "recovered successfully") {
		t.Error("recovery recover should report success")
	}
}

func TestBarrierRecoveryRecover_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		unsealSharesErr: errors.New("recovery failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRecoveryRecover(cfg, printer, []string{"rk-1"})
}

func TestBarrierRecoveryRecover_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRecoveryRecover(cfg, printer, []string{"rk-1"})
}

// --- barrierRecoveryDelete ---

func TestBarrierRecoveryDelete_Success(t *testing.T) {
	mock := &mockBarrierClient{}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRecoveryDelete(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "deleted") {
		t.Error("recovery delete should report deletion")
	}
}

func TestBarrierRecoveryDelete_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBarrierClient{
		sealBarrierErr: errors.New("delete failed"),
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRecoveryDelete(cfg, printer)
}

func TestBarrierRecoveryDelete_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := newBarrierErrorConfig()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierRecoveryDelete(cfg, printer)
}

// --- createBarrierClient ---

func TestCreateBarrierClient_Success(t *testing.T) {
	mock := &mockBarrierClient{}
	cfg := newBarrierConfig(mock)

	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		t.Fatalf("createBarrierClient should not error: %v", err)
	}
	defer cleanup()

	if cl == nil {
		t.Fatal("createBarrierClient should return a non-nil client")
	}
}

func TestCreateBarrierClient_ClientCreateError(t *testing.T) {
	cfg := newBarrierErrorConfig()

	_, _, err := createBarrierClient(cfg)
	if err == nil {
		t.Fatal("createBarrierClient should return an error when client creation fails")
	}
}

func TestCreateBarrierClient_ConnectError(t *testing.T) {
	mock := &mockBarrierClient{
		connectBarrierErr: errors.New("connect failed"),
	}
	cfg := newBarrierConfig(mock)

	_, _, err := createBarrierClient(cfg)
	if err == nil {
		t.Fatal("createBarrierClient should return an error when connect fails")
	}
}

// --- Output format tests ---

func TestBarrierInit_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mock := &mockBarrierClient{}
			cfg := newBarrierConfig(mock)

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			barrierInit(cfg, printer, "secret")

			if buf.Len() == 0 {
				t.Errorf("barrierInit with %s format should produce output", format)
			}
		})
	}
}

func TestBarrierSeal_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mock := &mockBarrierClient{}
			cfg := newBarrierConfig(mock)

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			barrierSeal(cfg, printer)

			if buf.Len() == 0 {
				t.Errorf("barrierSeal with %s format should produce output", format)
			}
		})
	}
}

func TestBarrierStatus_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mock := &mockBarrierClient{
				statusResp: &transport.BarrierStatusResponse{
					Sealed:         false,
					Strategy:       "password",
					HardwareBacked: false,
				},
			}
			cfg := newBarrierConfig(mock)

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			barrierStatus(cfg, printer)

			if buf.Len() == 0 {
				t.Errorf("barrierStatus with %s format should produce output", format)
			}
		})
	}
}

func TestBarrierUnsealWithShare_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mock := &mockBarrierClient{
				unsealShareResp: &transport.BarrierUnsealShareResponse{
					Required:  3,
					Submitted: 1,
					Complete:  false,
				},
			}
			cfg := newBarrierConfig(mock)

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			barrierUnsealWithShare(cfg, printer, "share-1")

			if buf.Len() == 0 {
				t.Errorf("barrierUnsealWithShare with %s format should produce output", format)
			}
		})
	}
}

func TestBarrierInitShamir_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mock := &mockBarrierClient{
				initShamirResp: &transport.BarrierInitializeShamirResponse{
					Shares:      []string{"s1", "s2", "s3"},
					Threshold:   2,
					TotalShares: 3,
				},
			}
			cfg := newBarrierConfig(mock)

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			barrierInitShamir(cfg, printer, "secret", 2, 3)

			if buf.Len() == 0 {
				t.Errorf("barrierInitShamir with %s format should produce output", format)
			}
		})
	}
}

func TestBarrierRecoveryGenerate_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mock := &mockBarrierClient{
				initShamirResp: &transport.BarrierInitializeShamirResponse{
					Shares:      []string{"rk-1", "rk-2"},
					Threshold:   1,
					TotalShares: 2,
				},
			}
			cfg := newBarrierConfig(mock)

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			barrierRecoveryGenerate(cfg, printer, 1, 2)

			if buf.Len() == 0 {
				t.Errorf("barrierRecoveryGenerate with %s format should produce output", format)
			}
		})
	}
}

// --- Sentinel error tests ---

func TestBarrierErrors_AreDistinct(t *testing.T) {
	sentinelErrors := []error{
		ErrBarrierUnsealNoInput,
		ErrBarrierRekeyParams,
		ErrBarrierRootTokenNoShares,
		ErrBarrierNotShamir,
		ErrBarrierInvalidShareIndex,
		ErrBarrierSharesDeleteNoIndex,
		ErrBarrierRecoveryParams,
		ErrBarrierRecoveryNoKeys,
	}

	for i, err1 := range sentinelErrors {
		if err1 == nil {
			t.Errorf("sentinel error at index %d should not be nil", i)
		}
		for j, err2 := range sentinelErrors {
			if i != j && err1.Error() == err2.Error() {
				t.Errorf("sentinel errors at indices %d and %d have the same message: %q",
					i, j, err1.Error())
			}
		}
	}
}

func TestBarrierErrors_ContainMeaningfulMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{"UnsealNoInput", ErrBarrierUnsealNoInput, "required"},
		{"RekeyParams", ErrBarrierRekeyParams, "positive"},
		{"RootTokenNoShares", ErrBarrierRootTokenNoShares, "required"},
		{"NotShamir", ErrBarrierNotShamir, "Shamir"},
		{"InvalidShareIndex", ErrBarrierInvalidShareIndex, "index"},
		{"SharesDeleteNoIndex", ErrBarrierSharesDeleteNoIndex, "index"},
		{"RecoveryParams", ErrBarrierRecoveryParams, "positive"},
		{"RecoveryNoKeys", ErrBarrierRecoveryNoKeys, "required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.err.Error(), tt.contains) {
				t.Errorf("error %q should contain %q", tt.err.Error(), tt.contains)
			}
		})
	}
}

// --- Client close tests ---

func TestBarrierInit_ClosesClient(t *testing.T) {
	mock := &mockBarrierClient{}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierInit(cfg, printer, "secret")

	if !mock.closeBarrierCalled {
		t.Error("barrierInit should close the client")
	}
}

func TestBarrierSeal_ClosesClient(t *testing.T) {
	mock := &mockBarrierClient{}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierSeal(cfg, printer)

	if !mock.closeBarrierCalled {
		t.Error("barrierSeal should close the client")
	}
}

func TestBarrierStatus_ClosesClient(t *testing.T) {
	mock := &mockBarrierClient{}
	cfg := newBarrierConfig(mock)
	mock.statusResp = &transport.BarrierStatusResponse{
		Sealed:   false,
		Strategy: "password",
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierStatus(cfg, printer)

	if !mock.closeBarrierCalled {
		t.Error("barrierStatus should close the client")
	}
}

func TestBarrierUnsealWithSecret_ClosesClient(t *testing.T) {
	mock := &mockBarrierClient{}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierUnsealWithSecret(cfg, printer, "secret")

	if !mock.closeBarrierCalled {
		t.Error("barrierUnsealWithSecret should close the client")
	}
}

func TestBarrierUnsealWithShares_ClosesClient(t *testing.T) {
	mock := &mockBarrierClient{}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierUnsealWithShares(cfg, printer, []string{"s1", "s2"})

	if !mock.closeBarrierCalled {
		t.Error("barrierUnsealWithShares should close the client")
	}
}

// --- Status without initialized_at ---

func TestBarrierStatus_WithoutInitializedAt(t *testing.T) {
	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:         true,
			Strategy:       "password",
			HardwareBacked: false,
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	barrierStatus(cfg, printer)

	output := buf.String()
	if strings.Contains(output, "initialized_at") {
		t.Error("status without initialized_at should not show that field")
	}
}

func TestBarrierStatus_TextWithoutInitializedAt(t *testing.T) {
	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:         false,
			Strategy:       "shamir",
			HardwareBacked: true,
		},
	}
	cfg := newBarrierConfig(mock)

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	barrierStatus(cfg, printer)

	output := buf.String()
	if strings.Contains(output, "Initialized At") {
		t.Error("text status without initialized_at should not show that field")
	}
}
