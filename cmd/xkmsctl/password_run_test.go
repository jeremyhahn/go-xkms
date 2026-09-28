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

// password_run_test.go exercises the "xkmsctl password" command tree's Run
// closures against mockPasswordClient (defined in password_test.go).
package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errPasswordRunBoom = errors.New("boom")

func TestPasswordAddCmd_Success(t *testing.T) {
	resetCmdFlags(t, passwordAddCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordAddCmd) })
	mock := &mockPasswordClient{addResp: &transport.PasswordAddResponse{
		ID: "id-1", Name: "github", CreatedAt: "2026-01-01T00:00:00Z",
	}}
	withGlobalConfig(t, newPasswordConfig(mock))
	_ = passwordAddCmd.Flags().Set("password", "s3cret")
	_ = passwordAddCmd.Flags().Set("username", "alice")

	out := captureStdout(t, func() {
		passwordAddCmd.Run(passwordAddCmd, []string{"github"})
	})
	if mock.gotAddReq == nil || mock.gotAddReq.Name != "github" ||
		mock.gotAddReq.Password != "s3cret" || mock.gotAddReq.Username != "alice" {
		t.Errorf("PasswordAdd request mismatch: %+v", mock.gotAddReq)
	}
	if !strings.Contains(out, "id-1") {
		t.Errorf("expected entry ID in output, got %q", out)
	}
}

func TestPasswordAddCmd_Error(t *testing.T) {
	resetCmdFlags(t, passwordAddCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordAddCmd) })
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{addErr: errPasswordRunBoom}))
	_ = passwordAddCmd.Flags().Set("password", "s3cret")

	code := captureExit(t, func() {
		passwordAddCmd.Run(passwordAddCmd, []string{"github"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPasswordAddCmd_PromptedSecret(t *testing.T) {
	resetCmdFlags(t, passwordAddCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordAddCmd) })
	mock := &mockPasswordClient{addResp: &transport.PasswordAddResponse{ID: "id-1", Name: "github"}}
	withGlobalConfig(t, newPasswordConfig(mock))
	withPromptInput(t, "prompted-secret\n")

	captureStdout(t, func() {
		passwordAddCmd.Run(passwordAddCmd, []string{"github"})
	})
	if mock.gotAddReq == nil || mock.gotAddReq.Password != "prompted-secret" {
		t.Errorf("expected prompted secret in request, got %+v", mock.gotAddReq)
	}
}

func TestPasswordGetCmd_Success(t *testing.T) {
	resetCmdFlags(t, passwordGetCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordGetCmd) })
	mock := &mockPasswordClient{getResp: &transport.PasswordGetResponse{
		ID: "id-1", Name: "github", Username: "alice", Password: "s3cret",
	}}
	withGlobalConfig(t, newPasswordConfig(mock))

	out := captureStdout(t, func() {
		passwordGetCmd.Run(passwordGetCmd, []string{"id-1"})
	})
	if mock.gotGetReq == nil || mock.gotGetReq.ID != "id-1" {
		t.Errorf("PasswordGet request mismatch: %+v", mock.gotGetReq)
	}
	if !strings.Contains(out, "github") {
		t.Errorf("expected entry name in output, got %q", out)
	}
}

func TestPasswordGetCmd_Error(t *testing.T) {
	resetCmdFlags(t, passwordGetCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordGetCmd) })
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{getErr: errPasswordRunBoom}))

	code := captureExit(t, func() {
		passwordGetCmd.Run(passwordGetCmd, []string{"id-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPasswordListCmd_Success(t *testing.T) {
	resetCmdFlags(t, passwordListCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordListCmd) })
	mock := &mockPasswordClient{listResp: &transport.PasswordListResponse{
		Passwords: []transport.PasswordGetResponse{{ID: "id-1", Name: "github"}},
	}}
	withGlobalConfig(t, newPasswordConfig(mock))

	out := captureStdout(t, func() {
		passwordListCmd.Run(passwordListCmd, nil)
	})
	if !strings.Contains(out, "github") {
		t.Errorf("expected entry name in list output, got %q", out)
	}
}

func TestPasswordListCmd_Error(t *testing.T) {
	resetCmdFlags(t, passwordListCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordListCmd) })
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{listErr: errPasswordRunBoom}))

	code := captureExit(t, func() {
		passwordListCmd.Run(passwordListCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPasswordUpdateCmd_Success(t *testing.T) {
	resetCmdFlags(t, passwordUpdateCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordUpdateCmd) })
	mock := &mockPasswordClient{}
	withGlobalConfig(t, newPasswordConfig(mock))
	_ = passwordUpdateCmd.Flags().Set("username", "bob")
	_ = passwordUpdateCmd.Flags().Set("password", "n3w")

	captureStdout(t, func() {
		passwordUpdateCmd.Run(passwordUpdateCmd, []string{"id-1"})
	})
	if mock.gotUpdateReq == nil || mock.gotUpdateReq.ID != "id-1" {
		t.Fatalf("PasswordUpdate request mismatch: %+v", mock.gotUpdateReq)
	}
	if mock.gotUpdateReq.Username == nil || *mock.gotUpdateReq.Username != "bob" {
		t.Errorf("expected username pointer 'bob', got %+v", mock.gotUpdateReq.Username)
	}
	if mock.gotUpdateReq.Password == nil || *mock.gotUpdateReq.Password != "n3w" {
		t.Errorf("expected password pointer 'n3w', got %+v", mock.gotUpdateReq.Password)
	}
	if mock.gotUpdateReq.Name != nil {
		t.Errorf("expected nil name pointer for unchanged flag, got %+v", mock.gotUpdateReq.Name)
	}
}

func TestPasswordUpdateCmd_Error(t *testing.T) {
	resetCmdFlags(t, passwordUpdateCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordUpdateCmd) })
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{updateErr: errPasswordRunBoom}))
	_ = passwordUpdateCmd.Flags().Set("username", "bob")

	code := captureExit(t, func() {
		passwordUpdateCmd.Run(passwordUpdateCmd, []string{"id-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPasswordDeleteCmd_Success(t *testing.T) {
	resetCmdFlags(t, passwordDeleteCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordDeleteCmd) })
	mock := &mockPasswordClient{}
	withGlobalConfig(t, newPasswordConfig(mock))

	captureStdout(t, func() {
		passwordDeleteCmd.Run(passwordDeleteCmd, []string{"id-1"})
	})
	if mock.gotDeleteReq == nil || mock.gotDeleteReq.ID != "id-1" {
		t.Errorf("PasswordDelete request mismatch: %+v", mock.gotDeleteReq)
	}
}

func TestPasswordDeleteCmd_Error(t *testing.T) {
	resetCmdFlags(t, passwordDeleteCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordDeleteCmd) })
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{deleteErr: errPasswordRunBoom}))

	code := captureExit(t, func() {
		passwordDeleteCmd.Run(passwordDeleteCmd, []string{"id-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPasswordUnlockCmd_Success(t *testing.T) {
	resetCmdFlags(t, passwordUnlockCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordUnlockCmd) })
	mock := &mockPasswordClient{}
	withGlobalConfig(t, newPasswordConfig(mock))
	_ = passwordUnlockCmd.Flags().Set("user-pin", "1234")

	captureStdout(t, func() {
		passwordUnlockCmd.Run(passwordUnlockCmd, nil)
	})
	if mock.gotUnlockReq == nil || mock.gotUnlockReq.UserPIN != "1234" {
		t.Errorf("PasswordStoreUnlock request mismatch: %+v", mock.gotUnlockReq)
	}
}

func TestPasswordUnlockCmd_Error(t *testing.T) {
	resetCmdFlags(t, passwordUnlockCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordUnlockCmd) })
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{unlockErr: errPasswordRunBoom}))
	_ = passwordUnlockCmd.Flags().Set("user-pin", "1234")

	code := captureExit(t, func() {
		passwordUnlockCmd.Run(passwordUnlockCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPasswordLockCmd_Success(t *testing.T) {
	mock := &mockPasswordClient{}
	withGlobalConfig(t, newPasswordConfig(mock))

	captureStdout(t, func() {
		passwordLockCmd.Run(passwordLockCmd, nil)
	})
	if !mock.lockCalled {
		t.Error("expected PasswordStoreLock to be called")
	}
}

func TestPasswordLockCmd_Error(t *testing.T) {
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{lockErr: errPasswordRunBoom}))

	code := captureExit(t, func() {
		passwordLockCmd.Run(passwordLockCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPasswordStatusCmd_Success(t *testing.T) {
	mock := &mockPasswordClient{statusResp: &transport.PasswordStoreStatusResponse{
		AccessMode: "session_based", IsLocked: true, PasswordCount: 3,
	}}
	withGlobalConfig(t, newPasswordConfig(mock))

	out := captureStdout(t, func() {
		passwordStatusCmd.Run(passwordStatusCmd, nil)
	})
	if !strings.Contains(out, "session_based") {
		t.Errorf("expected access mode in output, got %q", out)
	}
}

func TestPasswordStatusCmd_Error(t *testing.T) {
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{statusErr: errPasswordRunBoom}))

	code := captureExit(t, func() {
		passwordStatusCmd.Run(passwordStatusCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPasswordAccessModeCmd_Success(t *testing.T) {
	mock := &mockPasswordClient{}
	withGlobalConfig(t, newPasswordConfig(mock))

	captureStdout(t, func() {
		passwordAccessModeCmd.Run(passwordAccessModeCmd, []string{"session_based"})
	})
	if mock.gotSetModeReq == nil || mock.gotSetModeReq.Mode != "session_based" {
		t.Errorf("PasswordStoreSetAccessMode request mismatch: %+v", mock.gotSetModeReq)
	}
}

func TestPasswordAccessModeCmd_Error(t *testing.T) {
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{setModeErr: errPasswordRunBoom}))

	code := captureExit(t, func() {
		passwordAccessModeCmd.Run(passwordAccessModeCmd, []string{"pin_per_operation"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPasswordGenerateCmd_Success(t *testing.T) {
	resetCmdFlags(t, passwordGenerateCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordGenerateCmd) })
	mock := &mockPasswordClient{genResp: &transport.PasswordGenerateResponse{Password: "r4nd0m"}}
	withGlobalConfig(t, newPasswordConfig(mock))
	_ = passwordGenerateCmd.Flags().Set("length", "24")
	_ = passwordGenerateCmd.Flags().Set("symbols", "false")

	out := captureStdout(t, func() {
		passwordGenerateCmd.Run(passwordGenerateCmd, nil)
	})
	if mock.gotGenReq == nil || mock.gotGenReq.Length != 24 || mock.gotGenReq.Symbols {
		t.Errorf("PasswordGenerate request mismatch: %+v", mock.gotGenReq)
	}
	if !strings.Contains(out, "r4nd0m") {
		t.Errorf("expected generated password in output, got %q", out)
	}
}

func TestPasswordGenerateCmd_Error(t *testing.T) {
	resetCmdFlags(t, passwordGenerateCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordGenerateCmd) })
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{genErr: errPasswordRunBoom}))

	code := captureExit(t, func() {
		passwordGenerateCmd.Run(passwordGenerateCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPasswordCmd_ConnectError(t *testing.T) {
	resetCmdFlags(t, passwordListCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordListCmd) })
	mock := &mockPasswordClient{}
	mock.connectErr = errPasswordRunBoom
	withGlobalConfig(t, newPasswordConfig(mock))

	code := captureExit(t, func() {
		passwordListCmd.Run(passwordListCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}
