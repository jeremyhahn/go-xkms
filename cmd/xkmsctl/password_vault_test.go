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
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// withTerminalSequence fakes an interactive terminal whose no-echo reader
// returns the given secrets in order.
func withTerminalSequence(t *testing.T, secrets ...string) {
	t.Helper()
	origIsTerminal := isTerminalFn
	origReadPassword := readPasswordFn
	t.Cleanup(func() {
		isTerminalFn = origIsTerminal
		readPasswordFn = origReadPassword
	})
	isTerminalFn = func(int) bool { return true }
	readPasswordFn = func(int) ([]byte, error) {
		if len(secrets) == 0 {
			return nil, errPasswordRunBoom
		}
		next := secrets[0]
		secrets = secrets[1:]
		return []byte(next), nil
	}
}

func TestResolveVaultPassphrase(t *testing.T) {
	tests := []struct {
		name    string
		flag    string
		stdin   string
		want    string
		wantErr error
	}{
		{name: "flag value", flag: "correct horse", want: "correct horse"},
		{name: "stdin", flag: "-", stdin: "piped phrase\n", want: "piped phrase"},
		{name: "prompted line", stdin: "typed phrase\n", want: "typed phrase"},
		{name: "empty stdin", flag: "-", stdin: "", wantErr: ErrVaultPassphraseRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withPromptInput(t, tt.stdin)
			got, err := resolveVaultPassphrase(tt.flag)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("passphrase = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveNewVaultPassphrase_ConfirmsOnTerminal(t *testing.T) {
	withTerminalSequence(t, "new phrase", "new phrase")
	got, err := resolveNewVaultPassphrase("")
	if err != nil {
		t.Fatalf("resolveNewVaultPassphrase: %v", err)
	}
	if got != "new phrase" {
		t.Errorf("passphrase = %q, want %q", got, "new phrase")
	}
}

func TestResolveNewVaultPassphrase_Mismatch(t *testing.T) {
	withTerminalSequence(t, "new phrase", "typo phrase")
	if _, err := resolveNewVaultPassphrase(""); !errors.Is(err, ErrVaultPassphraseMismatch) {
		t.Fatalf("error = %v, want ErrVaultPassphraseMismatch", err)
	}
}

func TestResolveNewVaultPassphrase_FlagSkipsConfirmation(t *testing.T) {
	// A terminal that would fail a second read proves the flag value is
	// taken as-is, without a confirmation prompt.
	withTerminalSequence(t)
	got, err := resolveNewVaultPassphrase("from flag")
	if err != nil {
		t.Fatalf("resolveNewVaultPassphrase: %v", err)
	}
	if got != "from flag" {
		t.Errorf("passphrase = %q, want %q", got, "from flag")
	}
}

func TestPasswordUnlockCmd_EmptyPassphrase(t *testing.T) {
	resetCmdFlags(t, passwordUnlockCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordUnlockCmd) })
	mock := &mockPasswordClient{}
	withGlobalConfig(t, newPasswordConfig(mock))
	withPromptInput(t, "\n")

	if code := captureExit(t, func() { passwordUnlockCmd.Run(passwordUnlockCmd, nil) }); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if mock.gotUnlockReq != nil {
		t.Errorf("unlock must not be sent without a passphrase, got %+v", mock.gotUnlockReq)
	}
}

func TestPasswordVaultStatusCmd_Success(t *testing.T) {
	mock := &mockPasswordClient{vaultStatusResp: &transport.PasswordVaultStatusResponse{
		Initialized: true,
		Unlocked:    true,
		Factors: []transport.PasswordVaultFactor{
			{ID: "f-1", Factor: "passphrase", Label: "laptop", CreatedAt: "2026-09-30T00:00:00Z"},
		},
	}}
	withGlobalConfig(t, newPasswordConfig(mock))

	out := captureStdout(t, func() { passwordVaultStatusCmd.Run(passwordVaultStatusCmd, nil) })
	for _, want := range []string{"Initialized: true", "Unlocked:    true", "f-1", "passphrase", "laptop"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestPasswordVaultStatusCmd_Error(t *testing.T) {
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{vaultStatusErr: errPasswordRunBoom}))
	if code := captureExit(t, func() { passwordVaultStatusCmd.Run(passwordVaultStatusCmd, nil) }); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPasswordVaultEnrollCmd_FirstEnrollmentPrintsRecoveryCode(t *testing.T) {
	resetCmdFlags(t, passwordVaultEnrollCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordVaultEnrollCmd) })
	mock := &mockPasswordClient{vaultEnrollResp: &transport.PasswordVaultEnrollResponse{
		Factor:       transport.PasswordVaultFactor{ID: "f-1", Factor: "passphrase", Label: "laptop"},
		RecoveryCode: "ABCD-EFGH-IJKL",
	}}
	withGlobalConfig(t, newPasswordConfig(mock))
	_ = passwordVaultEnrollCmd.Flags().Set("passphrase", "correct horse")
	_ = passwordVaultEnrollCmd.Flags().Set("label", "laptop")

	out := captureStdout(t, func() { passwordVaultEnrollCmd.Run(passwordVaultEnrollCmd, nil) })
	req := mock.gotEnrollReq
	if req == nil || req.Factor != "passphrase" || req.Passphrase != "correct horse" || req.Label != "laptop" {
		t.Fatalf("enroll request mismatch: %+v", req)
	}
	for _, want := range []string{"f-1", "ABCD-EFGH-IJKL", "it will not be shown again"} {
		if !strings.Contains(out, want) {
			t.Errorf("enroll output missing %q:\n%s", want, out)
		}
	}
}

func TestPasswordVaultEnrollCmd_LaterEnrollmentHasNoRecoveryBanner(t *testing.T) {
	resetCmdFlags(t, passwordVaultEnrollCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordVaultEnrollCmd) })
	mock := &mockPasswordClient{vaultEnrollResp: &transport.PasswordVaultEnrollResponse{
		Factor: transport.PasswordVaultFactor{ID: "f-2", Factor: "passphrase"},
	}}
	withGlobalConfig(t, newPasswordConfig(mock))
	_ = passwordVaultEnrollCmd.Flags().Set("passphrase", "second phrase")

	out := captureStdout(t, func() { passwordVaultEnrollCmd.Run(passwordVaultEnrollCmd, nil) })
	if strings.Contains(out, "RECOVERY CODE") {
		t.Errorf("a later enrollment must not print a recovery banner:\n%s", out)
	}
}

func TestPasswordVaultEnrollCmd_JSONCarriesRecoveryCode(t *testing.T) {
	resetCmdFlags(t, passwordVaultEnrollCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordVaultEnrollCmd) })
	mock := &mockPasswordClient{vaultEnrollResp: &transport.PasswordVaultEnrollResponse{
		Factor:       transport.PasswordVaultFactor{ID: "f-1", Factor: "passphrase"},
		RecoveryCode: "ABCD-EFGH-IJKL",
	}}
	cfg := newPasswordConfig(mock)
	cfg.OutputFormat = "json"
	withGlobalConfig(t, cfg)
	_ = passwordVaultEnrollCmd.Flags().Set("passphrase", "correct horse")

	out := captureStdout(t, func() { passwordVaultEnrollCmd.Run(passwordVaultEnrollCmd, nil) })
	if !strings.Contains(out, `"recovery_code": "ABCD-EFGH-IJKL"`) {
		t.Errorf("JSON output missing the recovery code:\n%s", out)
	}
}

func TestPasswordVaultEnrollCmd_Error(t *testing.T) {
	resetCmdFlags(t, passwordVaultEnrollCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordVaultEnrollCmd) })
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{vaultEnrollErr: errPasswordRunBoom}))
	_ = passwordVaultEnrollCmd.Flags().Set("passphrase", "correct horse")

	if code := captureExit(t, func() { passwordVaultEnrollCmd.Run(passwordVaultEnrollCmd, nil) }); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPasswordVaultRotateCmd_KeepsLabel(t *testing.T) {
	resetCmdFlags(t, passwordVaultRotateCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordVaultRotateCmd) })
	mock := &mockPasswordClient{
		vaultStatusResp: &transport.PasswordVaultStatusResponse{Factors: []transport.PasswordVaultFactor{
			{ID: "f-1", Factor: "passphrase", Label: "laptop"},
		}},
		vaultRotateResp: &transport.PasswordVaultEnrollResponse{
			Factor: transport.PasswordVaultFactor{ID: "f-9", Factor: "passphrase", Label: "laptop"},
		},
	}
	withGlobalConfig(t, newPasswordConfig(mock))
	_ = passwordVaultRotateCmd.Flags().Set("factor-id", "f-1")
	_ = passwordVaultRotateCmd.Flags().Set("passphrase", "rotated phrase")

	out := captureStdout(t, func() { passwordVaultRotateCmd.Run(passwordVaultRotateCmd, nil) })
	req := mock.gotRotateReq
	if req == nil || req.FactorID != "f-1" || req.Passphrase != "rotated phrase" || req.Label != "laptop" {
		t.Fatalf("rotate request mismatch: %+v", req)
	}
	if !strings.Contains(out, "f-9") {
		t.Errorf("rotate output missing the new factor ID:\n%s", out)
	}
}

func TestPasswordVaultRotateCmd_MissingFactorID(t *testing.T) {
	resetCmdFlags(t, passwordVaultRotateCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordVaultRotateCmd) })
	mock := &mockPasswordClient{}
	withGlobalConfig(t, newPasswordConfig(mock))
	_ = passwordVaultRotateCmd.Flags().Set("passphrase", "rotated phrase")

	if code := captureExit(t, func() { passwordVaultRotateCmd.Run(passwordVaultRotateCmd, nil) }); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if mock.gotRotateReq != nil {
		t.Errorf("rotate must not be sent without a factor ID")
	}
}

func TestPasswordVaultRotateCmd_StatusError(t *testing.T) {
	resetCmdFlags(t, passwordVaultRotateCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordVaultRotateCmd) })
	mock := &mockPasswordClient{vaultStatusErr: errPasswordRunBoom}
	withGlobalConfig(t, newPasswordConfig(mock))
	_ = passwordVaultRotateCmd.Flags().Set("factor-id", "f-1")
	_ = passwordVaultRotateCmd.Flags().Set("passphrase", "rotated phrase")

	if code := captureExit(t, func() { passwordVaultRotateCmd.Run(passwordVaultRotateCmd, nil) }); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if mock.gotRotateReq != nil {
		t.Errorf("rotate must not be sent when the current label cannot be read")
	}
}

func TestPasswordVaultRemoveCmd_Success(t *testing.T) {
	resetCmdFlags(t, passwordVaultRemoveCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordVaultRemoveCmd) })
	mock := &mockPasswordClient{}
	withGlobalConfig(t, newPasswordConfig(mock))
	_ = passwordVaultRemoveCmd.Flags().Set("factor-id", "f-2")

	captureStdout(t, func() { passwordVaultRemoveCmd.Run(passwordVaultRemoveCmd, nil) })
	if mock.gotRemoveReq == nil || mock.gotRemoveReq.FactorID != "f-2" {
		t.Errorf("remove request mismatch: %+v", mock.gotRemoveReq)
	}
}

func TestPasswordVaultRemoveCmd_Errors(t *testing.T) {
	t.Run("missing factor id", func(t *testing.T) {
		resetCmdFlags(t, passwordVaultRemoveCmd)
		t.Cleanup(func() { resetCmdFlags(t, passwordVaultRemoveCmd) })
		withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{}))
		if code := captureExit(t, func() { passwordVaultRemoveCmd.Run(passwordVaultRemoveCmd, nil) }); code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
	})
	t.Run("server error", func(t *testing.T) {
		resetCmdFlags(t, passwordVaultRemoveCmd)
		t.Cleanup(func() { resetCmdFlags(t, passwordVaultRemoveCmd) })
		withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{vaultRemoveErr: errPasswordRunBoom}))
		_ = passwordVaultRemoveCmd.Flags().Set("factor-id", "f-2")
		if code := captureExit(t, func() { passwordVaultRemoveCmd.Run(passwordVaultRemoveCmd, nil) }); code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
	})
}

func TestPasswordVaultRecoverCmd_Success(t *testing.T) {
	resetCmdFlags(t, passwordVaultRecoverCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordVaultRecoverCmd) })
	mock := &mockPasswordClient{vaultRecoverResp: &transport.PasswordVaultEnrollResponse{
		Factor:       transport.PasswordVaultFactor{ID: "f-3", Factor: "passphrase"},
		RecoveryCode: "NEW-CODE-0001",
	}}
	withGlobalConfig(t, newPasswordConfig(mock))
	withPromptInput(t, "OLD-CODE-0000\n")
	_ = passwordVaultRecoverCmd.Flags().Set("recovery-code", "-")
	_ = passwordVaultRecoverCmd.Flags().Set("passphrase", "fresh phrase")

	out := captureStdout(t, func() { passwordVaultRecoverCmd.Run(passwordVaultRecoverCmd, nil) })
	req := mock.gotRecoverReq
	if req == nil || req.RecoveryCode != "OLD-CODE-0000" || req.Passphrase != "fresh phrase" || req.Factor != "passphrase" {
		t.Fatalf("recover request mismatch: %+v", req)
	}
	if !strings.Contains(out, "NEW-CODE-0001") || !strings.Contains(out, "it will not be shown again") {
		t.Errorf("recover output missing the new recovery code banner:\n%s", out)
	}
}

func TestPasswordVaultRecoverCmd_InputErrors(t *testing.T) {
	tests := []struct {
		name  string
		code  string
		pass  string
		stdin string
	}{
		{name: "both on stdin", code: "-", pass: "-", stdin: "x\n"},
		{name: "empty recovery code", code: "-", pass: "fresh phrase", stdin: "\n"},
		{name: "empty passphrase", code: "SOME-CODE", pass: "-", stdin: "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCmdFlags(t, passwordVaultRecoverCmd)
			t.Cleanup(func() { resetCmdFlags(t, passwordVaultRecoverCmd) })
			mock := &mockPasswordClient{}
			withGlobalConfig(t, newPasswordConfig(mock))
			withPromptInput(t, tt.stdin)
			_ = passwordVaultRecoverCmd.Flags().Set("recovery-code", tt.code)
			_ = passwordVaultRecoverCmd.Flags().Set("passphrase", tt.pass)

			if code := captureExit(t, func() { passwordVaultRecoverCmd.Run(passwordVaultRecoverCmd, nil) }); code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}
			if mock.gotRecoverReq != nil {
				t.Errorf("recover must not be sent, got %+v", mock.gotRecoverReq)
			}
		})
	}
}

func TestPasswordVaultRecoverCmd_ServerError(t *testing.T) {
	resetCmdFlags(t, passwordVaultRecoverCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordVaultRecoverCmd) })
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{vaultRecoverErr: errPasswordRunBoom}))
	_ = passwordVaultRecoverCmd.Flags().Set("recovery-code", "SOME-CODE")
	_ = passwordVaultRecoverCmd.Flags().Set("passphrase", "fresh phrase")

	if code := captureExit(t, func() { passwordVaultRecoverCmd.Run(passwordVaultRecoverCmd, nil) }); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPasswordVaultCmd_Registered(t *testing.T) {
	for _, verb := range []string{"status", "enroll", "rotate", "remove", "recover"} {
		if _, _, err := rootCmd.Find([]string{"password", "vault", verb}); err != nil {
			t.Errorf("password vault %s missing: %v", verb, err)
		}
	}
}
