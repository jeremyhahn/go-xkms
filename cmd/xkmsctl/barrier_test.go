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
	"os"
	"path/filepath"
	"strings"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// -----------------------------------------------------------------------------
// Test scaffolding
// -----------------------------------------------------------------------------

// mockBarrierClient is a recording mock for the SDK Client surface
// exercised by the barrier verbs. It embeds mockBackendsClient (which
// supplies the entire 100+ method Client interface) and overrides only
// the methods the barrier verbs call.
type mockBarrierClient struct {
	mockBackendsClient

	// Connect/Close
	connectErr  error
	closeCalled bool
	closeErr    error

	// Barrier ops
	initErr         error
	initReq         *transport.BarrierInitializeRequest
	initShamirResp  *transport.BarrierInitializeShamirResponse
	initShamirErr   error
	initShamirReq   *transport.BarrierInitializeShamirRequest
	unsealErr       error
	unsealReq       *transport.BarrierUnsealRequest
	unsealSharesErr error
	unsealSharesReq *transport.BarrierUnsealSharesRequest
	statusResp      *transport.BarrierStatusResponse
	statusErr       error
	sealErr         error
	rekeyResp       *transport.BarrierRekeyResponse
	rekeyErr        error
	rekeyReq        *transport.BarrierRekeyRequest
	genKeysResp     *transport.BarrierRecoveryKeysResponse
	genKeysErr      error
	genKeysReq      *transport.BarrierGenerateRecoveryKeysRequest
	recoverErr      error
	recoverReq      *transport.BarrierRecoverWithKeysRequest

	// PIN ops
	setSOPINReq    *transport.SetSOPINRequest
	setSOPINErr    error
	setUserPINReq  *transport.SetUserPINRequest
	setUserPINErr  error
	verifySOPINReq *transport.VerifySOPINRequest
	verifySOPINErr error
}

// Connect captures the connection invocation.
func (m *mockBarrierClient) Connect(_ context.Context) error { return m.connectErr }

// Close records that the client was closed by the verb cleanup path.
func (m *mockBarrierClient) Close() error {
	m.closeCalled = true
	return m.closeErr
}

func (m *mockBarrierClient) BarrierInitialize(_ context.Context, req *transport.BarrierInitializeRequest) error {
	m.initReq = req
	return m.initErr
}

func (m *mockBarrierClient) BarrierInitializeShamir(_ context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	m.initShamirReq = req
	return m.initShamirResp, m.initShamirErr
}

func (m *mockBarrierClient) BarrierUnseal(_ context.Context, req *transport.BarrierUnsealRequest) error {
	m.unsealReq = req
	return m.unsealErr
}

func (m *mockBarrierClient) BarrierUnsealWithShares(_ context.Context, req *transport.BarrierUnsealSharesRequest) error {
	m.unsealSharesReq = req
	return m.unsealSharesErr
}

func (m *mockBarrierClient) BarrierStatus(_ context.Context) (*transport.BarrierStatusResponse, error) {
	return m.statusResp, m.statusErr
}

func (m *mockBarrierClient) BarrierSeal(_ context.Context) error { return m.sealErr }

func (m *mockBarrierClient) BarrierRekey(_ context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	m.rekeyReq = req
	return m.rekeyResp, m.rekeyErr
}

func (m *mockBarrierClient) BarrierGenerateRecoveryKeys(_ context.Context, req *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	m.genKeysReq = req
	return m.genKeysResp, m.genKeysErr
}

func (m *mockBarrierClient) BarrierRecoverWithKeys(_ context.Context, req *transport.BarrierRecoverWithKeysRequest) error {
	m.recoverReq = req
	return m.recoverErr
}

func (m *mockBarrierClient) SetSOPIN(_ context.Context, req *transport.SetSOPINRequest) error {
	m.setSOPINReq = req
	return m.setSOPINErr
}

func (m *mockBarrierClient) SetUserPIN(_ context.Context, req *transport.SetUserPINRequest) error {
	m.setUserPINReq = req
	return m.setUserPINErr
}

func (m *mockBarrierClient) VerifySOPIN(_ context.Context, req *transport.VerifySOPINRequest) error {
	m.verifySOPINReq = req
	return m.verifySOPINErr
}

// newBarrierMockConfig returns a Config wired to the supplied mock
// client through ClientFactory.
func newBarrierMockConfig(mock *mockBarrierClient) *Config {
	return &Config{
		Backend:      "software",
		OutputFormat: "json",
		Protocol:     DefaultTransport,
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

// newBarrierClientErrorConfig returns a Config whose ClientFactory always
// errors, used to drive the failure-on-create branches.
func newBarrierClientErrorConfig() *Config {
	return &Config{
		Backend:      "software",
		OutputFormat: "json",
		Protocol:     DefaultTransport,
		ClientFactory: func(*Config) (client.Client, error) {
			return nil, errors.New("client creation failed")
		},
	}
}

// withGlobalConfig copies the supplied Config's field values into the
// package-level globalConfig struct for the duration of the test (and
// restores them via t.Cleanup). The global pointer is NEVER reassigned
// — root.go's PersistentFlags are bound to the address of the original
// struct's fields, so swapping the pointer would silently desync the
// CLI's flag layer.
func withGlobalConfig(t *testing.T, cfg *Config) {
	t.Helper()
	original := *globalConfig
	t.Cleanup(func() { *globalConfig = original })
	*globalConfig = *cfg
}

// resetBarrierFlags clears the package-level barrier flag state so
// tests do not leak values into each other.
func resetBarrierFlags(t *testing.T) {
	t.Helper()
	barrierSecret = ""
	barrierShares = nil
	barrierSharesFile = ""
	barrierThreshold = 0
	barrierTotal = 0
	barrierAssumeYes = false
	barrierStrategy = "passphrase"
	barrierFlagSOPin = ""
	barrierFlagUserPin = ""
	barrierRecoveryShs = nil
}

// -----------------------------------------------------------------------------
// Command tree structure
// -----------------------------------------------------------------------------

func TestBarrierCmd_HasCanonicalSubcommands(t *testing.T) {
	want := map[string]bool{
		"status":        false,
		"init":          false,
		"init-shamir":   false,
		"unseal":        false,
		"unseal-shares": false,
		"seal":          false,
		"rekey":         false,
		"recovery":      false,
	}
	for _, c := range barrierCmd.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("barrier subcommand %q missing", name)
		}
	}
}

func TestBarrierCmd_DoesNotExposeRetiredVerbs(t *testing.T) {
	retired := map[string]struct{}{
		"root-token": {},
		"shares":     {},
	}
	for _, c := range barrierCmd.Commands() {
		if _, hit := retired[c.Name()]; hit {
			t.Errorf("retired verb %q still attached to barrier command", c.Name())
		}
	}
}

func TestBarrierRecoveryCmd_HasCanonicalSubcommands(t *testing.T) {
	want := map[string]bool{"generate": false, "recover": false}
	for _, c := range barrierRecoveryCmd.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("barrier recovery subcommand %q missing", name)
		}
	}
}

func TestBarrierRecoveryCmd_DoesNotExposeDelete(t *testing.T) {
	for _, c := range barrierRecoveryCmd.Commands() {
		if c.Name() == "delete" {
			t.Error("retired verb 'recovery delete' still attached")
		}
	}
}

// -----------------------------------------------------------------------------
// validateInitFlags
// -----------------------------------------------------------------------------

func TestValidateInitFlags_Software_Success(t *testing.T) {
	if err := validateInitFlags("passphrase", "pp", "", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateInitFlags_Software_RequiresSecret(t *testing.T) {
	err := validateInitFlags("passphrase", "", "", "")
	if err == nil {
		t.Fatal("expected error for missing --passphrase")
	}
	var typed *BarrierSecretRequiredError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierSecretRequiredError, got %T: %v", err, err)
	}
}

func TestValidateInitFlags_None_RejectsSecret(t *testing.T) {
	err := validateInitFlags("none", "pp", "", "")
	var typed *BarrierSecretNotAllowedError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierSecretNotAllowedError, got %T: %v", err, err)
	}
}

func TestValidateInitFlags_None_RejectsPINs(t *testing.T) {
	cases := []struct {
		name           string
		soPin, userPin string
	}{
		{"so-pin only", "SO", ""},
		{"user-pin only", "", "USR"},
		{"both pins", "SO", "USR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInitFlags("none", "", tc.soPin, tc.userPin)
			var typed *PINsNotAllowedError
			if !errors.As(err, &typed) {
				t.Fatalf("expected PINsNotAllowedError, got %T: %v", err, err)
			}
			if typed.Strategy != "none" {
				t.Errorf("Strategy = %q, want \"none\"", typed.Strategy)
			}
		})
	}
}

func TestValidateInitFlags_Shamir_RoutedElsewhere(t *testing.T) {
	err := validateInitFlags("shamir", "pp", "", "")
	var typed *BarrierShamirOnInitError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierShamirOnInitError, got %T: %v", err, err)
	}
}

func TestValidateInitFlags_UnknownStrategy(t *testing.T) {
	err := validateInitFlags("bogus", "pp", "", "")
	var typed *BarrierStrategyError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierStrategyError, got %T: %v", err, err)
	}
}

func TestValidateInitFlags_PINPairRequired(t *testing.T) {
	cases := []struct {
		name           string
		soPin, userPin string
	}{
		{"so-pin without user-pin", "SO", ""},
		{"user-pin without so-pin", "", "USR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInitFlags("passphrase", "pp", tc.soPin, tc.userPin)
			var typed *PINPairError
			if !errors.As(err, &typed) {
				t.Fatalf("expected PINPairError, got %T: %v", err, err)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// runBarrierInitCmd
// -----------------------------------------------------------------------------

func TestRunBarrierInitCmd_Software_Success(t *testing.T) {
	resetBarrierFlags(t)
	barrierStrategy = "passphrase"
	barrierSecret = "pp"

	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierInitCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierInitCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.initReq == nil {
		t.Fatal("BarrierInitialize was not called")
	}
	if mock.initReq.Secret != "pp" {
		t.Errorf("Secret = %q, want %q", mock.initReq.Secret, "pp")
	}
	if !mock.closeCalled {
		t.Error("client cleanup did not close the client")
	}
	// No PINs supplied, so the PIN RPCs must not have been called.
	if mock.setSOPINReq != nil || mock.setUserPINReq != nil {
		t.Error("PIN RPCs called when no PINs were supplied")
	}
}

func TestRunBarrierInitCmd_None_NoSecretNoPINs(t *testing.T) {
	resetBarrierFlags(t)
	barrierStrategy = "none"

	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierInitCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierInitCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.initReq == nil {
		t.Fatal("BarrierInitialize was not called")
	}
	if mock.initReq.Secret != "" {
		t.Errorf("Secret = %q, want empty for strategy=none", mock.initReq.Secret)
	}
}

func TestRunBarrierInitCmd_None_RejectsPINs(t *testing.T) {
	resetBarrierFlags(t)
	barrierStrategy = "none"
	barrierFlagSOPin = "SO"
	barrierFlagUserPin = "USR"

	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierInitCmd
	cmd.SetOut(new(bytes.Buffer))
	err := runBarrierInitCmd(cmd, nil)
	var typed *PINsNotAllowedError
	if !errors.As(err, &typed) {
		t.Fatalf("expected PINsNotAllowedError, got %T: %v", err, err)
	}
	if mock.initReq != nil {
		t.Error("BarrierInitialize must not be called when validation fails")
	}
}

func TestRunBarrierInitCmd_Software_PINPairDispatched(t *testing.T) {
	resetBarrierFlags(t)
	barrierStrategy = "passphrase"
	barrierSecret = "pp"
	barrierFlagSOPin = "SO123"
	barrierFlagUserPin = "USR123"

	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierInitCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierInitCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.setSOPINReq == nil {
		t.Fatal("SetSOPIN was not called")
	}
	if mock.setSOPINReq.NewSOPIN != "SO123" || mock.setSOPINReq.CurrentSOPIN != "" {
		t.Errorf("SetSOPIN request = %+v, want NewSOPIN=SO123 CurrentSOPIN=\"\"", mock.setSOPINReq)
	}
	if mock.setUserPINReq == nil {
		t.Fatal("SetUserPIN was not called")
	}
	if mock.setUserPINReq.SOPIN != "SO123" || mock.setUserPINReq.NewUserPIN != "USR123" {
		t.Errorf("SetUserPIN request = %+v, want SOPIN=SO123 NewUserPIN=USR123", mock.setUserPINReq)
	}
}

func TestRunBarrierInitCmd_BarrierInitErrorBubbles(t *testing.T) {
	resetBarrierFlags(t)
	barrierStrategy = "passphrase"
	barrierSecret = "pp"

	mock := &mockBarrierClient{initErr: errors.New("boom")}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierInitCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierInitCmd(cmd, nil); err == nil {
		t.Fatal("expected error from BarrierInitialize")
	}
}

func TestRunBarrierInitCmd_SetSOPINErrorBubbles(t *testing.T) {
	resetBarrierFlags(t)
	barrierStrategy = "passphrase"
	barrierSecret = "pp"
	barrierFlagSOPin = "SO"
	barrierFlagUserPin = "USR"

	mock := &mockBarrierClient{setSOPINErr: errors.New("pin failed")}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierInitCmd
	cmd.SetOut(new(bytes.Buffer))
	err := runBarrierInitCmd(cmd, nil)
	if err == nil {
		t.Fatal("expected error when SetSOPIN fails")
	}
	if !strings.Contains(err.Error(), "set SO PIN") {
		t.Errorf("error %q does not mention SetSOPIN", err.Error())
	}
}

func TestRunBarrierInitCmd_ClientFactoryError(t *testing.T) {
	resetBarrierFlags(t)
	barrierStrategy = "passphrase"
	barrierSecret = "pp"

	withGlobalConfig(t, newBarrierClientErrorConfig())

	cmd := barrierInitCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierInitCmd(cmd, nil); err == nil {
		t.Fatal("expected error when client creation fails")
	}
}

func TestRunBarrierInitCmd_ConnectError(t *testing.T) {
	resetBarrierFlags(t)
	barrierStrategy = "passphrase"
	barrierSecret = "pp"

	mock := &mockBarrierClient{connectErr: errors.New("dial failed")}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierInitCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierInitCmd(cmd, nil); err == nil {
		t.Fatal("expected error when Connect fails")
	}
}

// -----------------------------------------------------------------------------
// validateInitShamirFlags / runBarrierInitShamirCmd
// -----------------------------------------------------------------------------

func TestValidateInitShamirFlags_Success(t *testing.T) {
	if err := validateInitShamirFlags("pp", 3, 5, "", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateInitShamirFlags_MissingSecret(t *testing.T) {
	err := validateInitShamirFlags("", 3, 5, "", "")
	var typed *BarrierSecretRequiredError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierSecretRequiredError, got %T: %v", err, err)
	}
}

func TestValidateInitShamirFlags_ThresholdZero(t *testing.T) {
	err := validateInitShamirFlags("pp", 0, 5, "", "")
	var typed *BarrierShamirParamsError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierShamirParamsError, got %T", err)
	}
}

func TestValidateInitShamirFlags_TotalZero(t *testing.T) {
	err := validateInitShamirFlags("pp", 3, 0, "", "")
	var typed *BarrierShamirParamsError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierShamirParamsError, got %T", err)
	}
}

func TestValidateInitShamirFlags_ThresholdExceedsTotal(t *testing.T) {
	err := validateInitShamirFlags("pp", 5, 3, "", "")
	var typed *BarrierShamirParamsError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierShamirParamsError, got %T", err)
	}
}

func TestRunBarrierInitShamirCmd_Success(t *testing.T) {
	resetBarrierFlags(t)
	barrierSecret = "pp"
	barrierThreshold = 2
	barrierTotal = 3

	mock := &mockBarrierClient{
		initShamirResp: &transport.BarrierInitializeShamirResponse{
			Threshold:   2,
			TotalShares: 3,
			ShareCount:  3,
		},
	}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	out := new(bytes.Buffer)
	cmd := barrierInitShamirCmd
	cmd.SetOut(out)
	if err := runBarrierInitShamirCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.initShamirReq == nil {
		t.Fatal("BarrierInitializeShamir was not called")
	}
	if mock.initShamirReq.Threshold != 2 || mock.initShamirReq.TotalShares != 3 {
		t.Errorf("request = %+v, want threshold=2 total=3", mock.initShamirReq)
	}
	// Share-free contract: output reports metadata only, never share material.
	if !strings.Contains(out.String(), "\"share_count\": 3") {
		t.Errorf("output should include the share-count metadata; got %q", out.String())
	}
	if strings.Contains(out.String(), "\"shares\"") {
		t.Errorf("output must not include share material; got %q", out.String())
	}
}

func TestRunBarrierInitShamirCmd_PINPairDispatched(t *testing.T) {
	resetBarrierFlags(t)
	barrierSecret = "pp"
	barrierThreshold = 2
	barrierTotal = 3
	barrierFlagSOPin = "SO"
	barrierFlagUserPin = "USR"

	mock := &mockBarrierClient{
		initShamirResp: &transport.BarrierInitializeShamirResponse{
			Threshold:   2,
			TotalShares: 3,
			ShareCount:  3,
		},
	}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierInitShamirCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierInitShamirCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.setSOPINReq == nil || mock.setUserPINReq == nil {
		t.Error("expected PIN RPCs to be dispatched after init-shamir")
	}
}

// -----------------------------------------------------------------------------
// runBarrierUnsealCmd
// -----------------------------------------------------------------------------

func TestRunBarrierUnsealCmd_Success(t *testing.T) {
	resetBarrierFlags(t)
	barrierSecret = "pp"

	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierUnsealCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierUnsealCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.unsealReq == nil || mock.unsealReq.Secret != "pp" {
		t.Errorf("BarrierUnseal req = %+v, want Secret=pp", mock.unsealReq)
	}
}

func TestRunBarrierUnsealCmd_MissingSecret(t *testing.T) {
	resetBarrierFlags(t)

	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierUnsealCmd
	cmd.SetOut(new(bytes.Buffer))
	err := runBarrierUnsealCmd(cmd, nil)
	var typed *BarrierSecretRequiredError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierSecretRequiredError, got %T: %v", err, err)
	}
}

func TestRunBarrierUnsealCmd_BackendErrorBubbles(t *testing.T) {
	resetBarrierFlags(t)
	barrierSecret = "pp"

	mock := &mockBarrierClient{unsealErr: errors.New("denied")}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierUnsealCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierUnsealCmd(cmd, nil); err == nil {
		t.Fatal("expected error from BarrierUnseal")
	}
}

// -----------------------------------------------------------------------------
// resolveUnsealShares / runBarrierUnsealSharesCmd
// -----------------------------------------------------------------------------

func TestResolveUnsealShares_FlagsOnly(t *testing.T) {
	got, err := resolveUnsealShares([]string{"a", "b"}, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("got = %v, want [a b]", got)
	}
}

func TestResolveUnsealShares_NeitherSupplied(t *testing.T) {
	_, err := resolveUnsealShares(nil, "", nil)
	var typed *BarrierShareInputError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierShareInputError, got %T: %v", err, err)
	}
}

func TestResolveUnsealShares_BothSupplied(t *testing.T) {
	_, err := resolveUnsealShares([]string{"a"}, "/some/file", nil)
	var typed *BarrierShareInputError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierShareInputError, got %T: %v", err, err)
	}
}

func TestResolveUnsealShares_FileReadsLines(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "shares.txt")
	if err := os.WriteFile(tmp, []byte("alpha\n# comment\n\nbeta\n   \ngamma\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveUnsealShares(nil, tmp, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 || got[0] != "alpha" || got[1] != "beta" || got[2] != "gamma" {
		t.Errorf("got = %v, want [alpha beta gamma]", got)
	}
}

func TestResolveUnsealShares_FileMissing(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "missing.txt")
	_, err := resolveUnsealShares(nil, tmp, nil)
	var typed *BarrierSharesFileError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierSharesFileError, got %T: %v", err, err)
	}
}

func TestResolveUnsealShares_FileEmpty(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(tmp, []byte("# only comments\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := resolveUnsealShares(nil, tmp, nil)
	var typed *BarrierSharesFileEmptyError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierSharesFileEmptyError, got %T: %v", err, err)
	}
}

func TestResolveUnsealShares_StdinReads(t *testing.T) {
	stdin := strings.NewReader("share-x\nshare-y\n")
	got, err := resolveUnsealShares(nil, "-", stdin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "share-x" || got[1] != "share-y" {
		t.Errorf("got = %v, want [share-x share-y]", got)
	}
}

func TestRunBarrierUnsealSharesCmd_Success(t *testing.T) {
	resetBarrierFlags(t)
	barrierShares = []string{"a", "b", "c"}

	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierUnsealSharesCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierUnsealSharesCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.unsealSharesReq == nil || len(mock.unsealSharesReq.Shares) != 3 {
		t.Errorf("expected 3 shares submitted, got %+v", mock.unsealSharesReq)
	}
}

func TestRunBarrierUnsealSharesCmd_NoInput(t *testing.T) {
	resetBarrierFlags(t)

	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierUnsealSharesCmd
	cmd.SetOut(new(bytes.Buffer))
	err := runBarrierUnsealSharesCmd(cmd, nil)
	var typed *BarrierShareInputError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierShareInputError, got %T: %v", err, err)
	}
}

// -----------------------------------------------------------------------------
// runBarrierSealCmd
// -----------------------------------------------------------------------------

func TestConfirmBarrierSeal_AssumeYes(t *testing.T) {
	ok, err := confirmBarrierSeal(nil, new(bytes.Buffer), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("assume-yes must return ok=true")
	}
}

func TestConfirmBarrierSeal_Yes(t *testing.T) {
	ok, err := confirmBarrierSeal(strings.NewReader("yes\n"), new(bytes.Buffer), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("yes response must return ok=true")
	}
}

func TestConfirmBarrierSeal_No(t *testing.T) {
	ok, err := confirmBarrierSeal(strings.NewReader("no\n"), new(bytes.Buffer), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("no response must return ok=false")
	}
}

func TestConfirmBarrierSeal_StdinError(t *testing.T) {
	_, err := confirmBarrierSeal(strings.NewReader(""), new(bytes.Buffer), false)
	var typed *BarrierSealConfirmationError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierSealConfirmationError, got %T: %v", err, err)
	}
}

func TestRunBarrierSealCmd_AssumeYesSeals(t *testing.T) {
	resetBarrierFlags(t)
	barrierAssumeYes = true

	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierSealCmd
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetIn(strings.NewReader(""))
	if err := runBarrierSealCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunBarrierSealCmd_CancelOnNo(t *testing.T) {
	resetBarrierFlags(t)

	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	out := new(bytes.Buffer)
	cmd := barrierSealCmd
	cmd.SetOut(out)
	cmd.SetIn(strings.NewReader("no\n"))
	if err := runBarrierSealCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "Seal cancelled") {
		t.Errorf("output should mention cancellation; got %q", out.String())
	}
	if mock.closeCalled {
		t.Error("client should not be created when seal is cancelled")
	}
}

func TestRunBarrierSealCmd_SOPinVerifiedBeforeSeal(t *testing.T) {
	resetBarrierFlags(t)
	barrierAssumeYes = true
	barrierFlagSOPin = "SO12345"

	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierSealCmd
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetIn(strings.NewReader(""))
	if err := runBarrierSealCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.verifySOPINReq == nil {
		t.Fatal("VerifySOPIN was not called")
	}
	if mock.verifySOPINReq.SOPIN != "SO12345" {
		t.Errorf("VerifySOPIN SOPIN = %q, want SO12345", mock.verifySOPINReq.SOPIN)
	}
}

func TestRunBarrierSealCmd_SOPinVerifyErrorAborts(t *testing.T) {
	resetBarrierFlags(t)
	barrierAssumeYes = true
	barrierFlagSOPin = "BAD"

	mock := &mockBarrierClient{
		verifySOPINErr: errors.New("invalid pin"),
		// BarrierSeal must NOT be invoked when verification fails.
		sealErr: errors.New("should not be called"),
	}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierSealCmd
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetIn(strings.NewReader(""))
	err := runBarrierSealCmd(cmd, nil)
	if err == nil {
		t.Fatal("expected error when VerifySOPIN fails")
	}
	if !strings.Contains(err.Error(), "verify SO PIN") {
		t.Errorf("error %q does not mention VerifySOPIN", err.Error())
	}
}

// -----------------------------------------------------------------------------
// validateRekeyFlags / runBarrierRekeyCmd
// -----------------------------------------------------------------------------

func TestValidateRekeyFlags_ShamirParamsRequired(t *testing.T) {
	err := validateRekeyFlags(0, 0)
	var typed *XKMSRekeyShamirParamsRequiredError
	if !errors.As(err, &typed) {
		t.Fatalf("expected XKMSRekeyShamirParamsRequiredError, got %T: %v", err, err)
	}
}

func TestValidateRekeyFlags_ShamirSuccess(t *testing.T) {
	if err := validateRekeyFlags(3, 5); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBarrierRekeyCmd_PassphraseFlagRemoved(t *testing.T) {
	if barrierRekeyCmd.Flags().Lookup("passphrase") != nil {
		t.Fatal("barrier rekey must not expose --passphrase: the server " +
			"generates the fresh secret material itself (no secret on the wire)")
	}
}

func TestValidateRekeyFlags_UnpairedShamirFlags(t *testing.T) {
	cases := []struct {
		threshold, total int
	}{
		{3, 0},
		{0, 5},
	}
	for _, tc := range cases {
		err := validateRekeyFlags(tc.threshold, tc.total)
		var typed *BarrierShamirParamsError
		if !errors.As(err, &typed) {
			t.Fatalf("expected BarrierShamirParamsError for threshold=%d total=%d, got %T", tc.threshold, tc.total, err)
		}
	}
}

func TestValidateRekeyFlags_ThresholdExceedsTotal(t *testing.T) {
	err := validateRekeyFlags(5, 3)
	var typed *BarrierShamirParamsError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierShamirParamsError, got %T", err)
	}
}

func TestRunBarrierRekeyCmd_Success(t *testing.T) {
	resetBarrierFlags(t)
	barrierThreshold = 3
	barrierTotal = 5

	mock := &mockBarrierClient{
		rekeyResp: &transport.BarrierRekeyResponse{
			Threshold:   3,
			TotalShares: 5,
			ShareCount:  5,
		},
	}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierRekeyCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierRekeyCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.rekeyReq == nil || mock.rekeyReq.Threshold != 3 || mock.rekeyReq.Total != 5 {
		t.Errorf("rekey req = %+v, want threshold=3 total=5", mock.rekeyReq)
	}
}

func TestRunBarrierRekeyCmd_SOPinVerified(t *testing.T) {
	resetBarrierFlags(t)
	barrierThreshold = 3
	barrierTotal = 5
	barrierFlagSOPin = "SO"

	mock := &mockBarrierClient{
		rekeyResp: &transport.BarrierRekeyResponse{
			Threshold:   3,
			TotalShares: 5,
			ShareCount:  5,
		},
	}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierRekeyCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierRekeyCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.verifySOPINReq == nil || mock.verifySOPINReq.SOPIN != "SO" {
		t.Errorf("expected VerifySOPIN to be called with SO; got %+v", mock.verifySOPINReq)
	}
}

// -----------------------------------------------------------------------------
// validateRecoveryGenerateFlags / runBarrierRecoveryGenerateCmd
// -----------------------------------------------------------------------------

func TestValidateRecoveryGenerateFlags_Success(t *testing.T) {
	if err := validateRecoveryGenerateFlags(3, 5); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRecoveryGenerateFlags_ThresholdTooSmall(t *testing.T) {
	err := validateRecoveryGenerateFlags(1, 5)
	var typed *BarrierShamirParamsError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierShamirParamsError, got %T", err)
	}
}

func TestValidateRecoveryGenerateFlags_TotalLessThanThreshold(t *testing.T) {
	err := validateRecoveryGenerateFlags(3, 2)
	var typed *BarrierShamirParamsError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierShamirParamsError, got %T", err)
	}
}

func TestRunBarrierRecoveryGenerateCmd_Success(t *testing.T) {
	resetBarrierFlags(t)
	barrierThreshold = 2
	barrierTotal = 3

	mock := &mockBarrierClient{
		genKeysResp: &transport.BarrierRecoveryKeysResponse{
			Threshold:   2,
			TotalShares: 3,
			ShareCount:  3,
		},
	}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	out := new(bytes.Buffer)
	cmd := barrierRecoveryGenerateCmd
	cmd.SetOut(out)
	if err := runBarrierRecoveryGenerateCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.genKeysReq == nil || mock.genKeysReq.Threshold != 2 || mock.genKeysReq.Total != 3 {
		t.Errorf("gen-keys req = %+v, want threshold=2 total=3", mock.genKeysReq)
	}
	// Share-free contract: output reports metadata only, never key material.
	if !strings.Contains(out.String(), "\"share_count\": 3") {
		t.Errorf("expected recovery metadata in output; got %q", out.String())
	}
	if strings.Contains(out.String(), "\"recovery_keys\"") {
		t.Errorf("output must not include recovery key material; got %q", out.String())
	}
}

// -----------------------------------------------------------------------------
// runBarrierRecoveryRecoverCmd
// -----------------------------------------------------------------------------

func TestRunBarrierRecoveryRecoverCmd_Success(t *testing.T) {
	resetBarrierFlags(t)
	barrierRecoveryShs = []string{"rk-1", "rk-2"}

	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierRecoveryRecoverCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierRecoveryRecoverCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.recoverReq == nil || len(mock.recoverReq.Keys) != 2 {
		t.Errorf("recover req = %+v, want 2 keys", mock.recoverReq)
	}
}

func TestRunBarrierRecoveryRecoverCmd_MissingShares(t *testing.T) {
	resetBarrierFlags(t)

	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierRecoveryRecoverCmd
	cmd.SetOut(new(bytes.Buffer))
	err := runBarrierRecoveryRecoverCmd(cmd, nil)
	var typed *BarrierRecoverySharesRequiredError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierRecoverySharesRequiredError, got %T: %v", err, err)
	}
}

// -----------------------------------------------------------------------------
// runBarrierStatusCmd
// -----------------------------------------------------------------------------

func TestRunBarrierStatusCmd_Success(t *testing.T) {
	resetBarrierFlags(t)

	mock := &mockBarrierClient{
		statusResp: &transport.BarrierStatusResponse{
			Sealed:         false,
			Strategy:       "passphrase",
			HardwareBacked: false,
			InitializedAt:  "2025-01-01T00:00:00Z",
		},
	}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	out := new(bytes.Buffer)
	cmd := barrierStatusCmd
	cmd.SetOut(out)
	if err := runBarrierStatusCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "passphrase") {
		t.Errorf("expected strategy in output; got %q", out.String())
	}
}

func TestRunBarrierStatusCmd_Error(t *testing.T) {
	resetBarrierFlags(t)

	mock := &mockBarrierClient{statusErr: errors.New("rpc failed")}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierStatusCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierStatusCmd(cmd, nil); err == nil {
		t.Fatal("expected error from BarrierStatus")
	}
}

// -----------------------------------------------------------------------------
// Typed error coverage
// -----------------------------------------------------------------------------

func TestTypedErrorMessages(t *testing.T) {
	cases := []struct {
		err      error
		contains string
	}{
		{&PINsNotAllowedError{Strategy: "none", Op: "init"}, "--barrier-strategy=none"},
		{&BarrierStrategyError{}, "--barrier-strategy is required"},
		{&BarrierStrategyError{Value: "bogus"}, "bogus"},
		{&BarrierSecretRequiredError{Op: "init", Strategy: "passphrase"}, "--passphrase is required"},
		{&BarrierSecretNotAllowedError{Op: "init", Strategy: "none"}, "not allowed"},
		{&PINPairError{Op: "init", Missing: "--so-pin"}, "--so-pin"},
		{&BarrierShamirParamsError{Op: "init-shamir", Reason: "--threshold must be > 0"}, "threshold"},
		{&BarrierShamirOnInitError{}, "init-shamir"},
		{&BarrierShareInputError{Reason: "one of"}, "unseal-shares"},
		{&BarrierSharesFileError{Path: "/x", Err: errors.New("oops")}, "/x"},
		{&BarrierSharesFileEmptyError{Path: "/x"}, "/x"},
		{&XKMSRekeyShamirParamsRequiredError{}, "Shamir"},
		{&BarrierRecoverySharesRequiredError{}, "--share is required"},
		{&BarrierSealConfirmationError{Err: errors.New("eof")}, "eof"},
	}
	for _, tc := range cases {
		if !strings.Contains(tc.err.Error(), tc.contains) {
			t.Errorf("error %q does not contain %q", tc.err.Error(), tc.contains)
		}
	}
}

func TestBarrierSharesFileError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &BarrierSharesFileError{Path: "/x", Err: inner}
	if !errors.Is(err, inner) {
		t.Error("BarrierSharesFileError should unwrap to its inner error")
	}
}

func TestBarrierSealConfirmationError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &BarrierSealConfirmationError{Err: inner}
	if !errors.Is(err, inner) {
		t.Error("BarrierSealConfirmationError should unwrap to its inner error")
	}
}
