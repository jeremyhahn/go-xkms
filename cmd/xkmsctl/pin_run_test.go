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

// pin_run_test.go exercises the "xkmsctl pin" command tree against a mock
// PINService, covering the happy path and error handling for each subcommand
// plus interactive PIN prompting.
package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errPinRunBoom = errors.New("boom")

// mockPINClient implements the PINService subset of client.Client used by the
// pin commands; every other method comes from the embedded base.
type mockPINClient struct {
	mockBackendsClient

	setSOErr      error
	setUserErr    error
	changeSOErr   error
	changeUserErr error
	verifySOErr   error
	verifyUserErr error
	lockoutResp   *transport.LockoutStatusResponse
	lockoutErr    error
	resetErr      error

	gotSetSOReq      *transport.SetSOPINRequest
	gotSetUserReq    *transport.SetUserPINRequest
	gotChangeSOReq   *transport.ChangeSOPINRequest
	gotChangeUserReq *transport.ChangeUserPINRequest
	gotVerifySOReq   *transport.VerifySOPINRequest
	gotVerifyUserReq *transport.VerifyUserPINRequest
	gotResetReq      *transport.ResetLockoutRequest
}

func (m *mockPINClient) SetSOPIN(_ context.Context, req *transport.SetSOPINRequest) error {
	m.gotSetSOReq = req
	return m.setSOErr
}

func (m *mockPINClient) SetUserPIN(_ context.Context, req *transport.SetUserPINRequest) error {
	m.gotSetUserReq = req
	return m.setUserErr
}

func (m *mockPINClient) ChangeSOPIN(_ context.Context, req *transport.ChangeSOPINRequest) error {
	m.gotChangeSOReq = req
	return m.changeSOErr
}

func (m *mockPINClient) ChangeUserPIN(_ context.Context, req *transport.ChangeUserPINRequest) error {
	m.gotChangeUserReq = req
	return m.changeUserErr
}

func (m *mockPINClient) VerifySOPIN(_ context.Context, req *transport.VerifySOPINRequest) error {
	m.gotVerifySOReq = req
	return m.verifySOErr
}

func (m *mockPINClient) VerifyUserPIN(_ context.Context, req *transport.VerifyUserPINRequest) error {
	m.gotVerifyUserReq = req
	return m.verifyUserErr
}

func (m *mockPINClient) GetLockoutStatus(_ context.Context) (*transport.LockoutStatusResponse, error) {
	return m.lockoutResp, m.lockoutErr
}

func (m *mockPINClient) ResetLockout(_ context.Context, req *transport.ResetLockoutRequest) error {
	m.gotResetReq = req
	return m.resetErr
}

func newPINConfig(mock *mockPINClient) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func TestPinSOSetCmd_Success(t *testing.T) {
	resetCmdFlags(t, pinSOSetCmd)
	t.Cleanup(func() { resetCmdFlags(t, pinSOSetCmd) })
	mock := &mockPINClient{}
	withGlobalConfig(t, newPINConfig(mock))
	_ = pinSOSetCmd.Flags().Set("new-pin", "123456")

	captureStdout(t, func() {
		pinSOSetCmd.Run(pinSOSetCmd, nil)
	})
	if mock.gotSetSOReq == nil || mock.gotSetSOReq.NewSOPIN != "123456" {
		t.Errorf("SetSOPIN request mismatch: %+v", mock.gotSetSOReq)
	}
}

func TestPinSOSetCmd_PromptedPIN(t *testing.T) {
	resetCmdFlags(t, pinSOSetCmd)
	t.Cleanup(func() { resetCmdFlags(t, pinSOSetCmd) })
	mock := &mockPINClient{}
	withGlobalConfig(t, newPINConfig(mock))
	withPromptInput(t, "prompted-pin\n")

	captureStdout(t, func() {
		pinSOSetCmd.Run(pinSOSetCmd, nil)
	})
	if mock.gotSetSOReq == nil || mock.gotSetSOReq.NewSOPIN != "prompted-pin" {
		t.Errorf("expected prompted PIN, got %+v", mock.gotSetSOReq)
	}
}

func TestPinSOSetCmd_Error(t *testing.T) {
	resetCmdFlags(t, pinSOSetCmd)
	t.Cleanup(func() { resetCmdFlags(t, pinSOSetCmd) })
	withGlobalConfig(t, newPINConfig(&mockPINClient{setSOErr: errPinRunBoom}))
	_ = pinSOSetCmd.Flags().Set("new-pin", "123456")

	code := captureExit(t, func() {
		pinSOSetCmd.Run(pinSOSetCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPinSOChangeCmd_SuccessAndError(t *testing.T) {
	resetCmdFlags(t, pinSOChangeCmd)
	t.Cleanup(func() { resetCmdFlags(t, pinSOChangeCmd) })
	mock := &mockPINClient{}
	withGlobalConfig(t, newPINConfig(mock))
	_ = pinSOChangeCmd.Flags().Set("current-pin", "old")
	_ = pinSOChangeCmd.Flags().Set("new-pin", "new")
	captureStdout(t, func() {
		pinSOChangeCmd.Run(pinSOChangeCmd, nil)
	})
	if mock.gotChangeSOReq == nil || mock.gotChangeSOReq.CurrentSOPIN != "old" || mock.gotChangeSOReq.NewSOPIN != "new" {
		t.Errorf("ChangeSOPIN request mismatch: %+v", mock.gotChangeSOReq)
	}

	resetCmdFlags(t, pinSOChangeCmd)
	withGlobalConfig(t, newPINConfig(&mockPINClient{changeSOErr: errPinRunBoom}))
	_ = pinSOChangeCmd.Flags().Set("current-pin", "old")
	_ = pinSOChangeCmd.Flags().Set("new-pin", "new")
	code := captureExit(t, func() {
		pinSOChangeCmd.Run(pinSOChangeCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPinSOVerifyCmd_SuccessAndError(t *testing.T) {
	resetCmdFlags(t, pinSOVerifyCmd)
	t.Cleanup(func() { resetCmdFlags(t, pinSOVerifyCmd) })
	mock := &mockPINClient{}
	withGlobalConfig(t, newPINConfig(mock))
	_ = pinSOVerifyCmd.Flags().Set("pin", "123456")
	captureStdout(t, func() {
		pinSOVerifyCmd.Run(pinSOVerifyCmd, nil)
	})
	if mock.gotVerifySOReq == nil || mock.gotVerifySOReq.SOPIN != "123456" {
		t.Errorf("VerifySOPIN request mismatch: %+v", mock.gotVerifySOReq)
	}

	resetCmdFlags(t, pinSOVerifyCmd)
	withGlobalConfig(t, newPINConfig(&mockPINClient{verifySOErr: errPinRunBoom}))
	_ = pinSOVerifyCmd.Flags().Set("pin", "123456")
	code := captureExit(t, func() {
		pinSOVerifyCmd.Run(pinSOVerifyCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPinUserSetCmd_SuccessAndError(t *testing.T) {
	resetCmdFlags(t, pinUserSetCmd)
	t.Cleanup(func() { resetCmdFlags(t, pinUserSetCmd) })
	mock := &mockPINClient{}
	withGlobalConfig(t, newPINConfig(mock))
	_ = pinUserSetCmd.Flags().Set("so-pin", "so")
	_ = pinUserSetCmd.Flags().Set("new-pin", "user")
	captureStdout(t, func() {
		pinUserSetCmd.Run(pinUserSetCmd, nil)
	})
	if mock.gotSetUserReq == nil || mock.gotSetUserReq.SOPIN != "so" || mock.gotSetUserReq.NewUserPIN != "user" {
		t.Errorf("SetUserPIN request mismatch: %+v", mock.gotSetUserReq)
	}

	resetCmdFlags(t, pinUserSetCmd)
	withGlobalConfig(t, newPINConfig(&mockPINClient{setUserErr: errPinRunBoom}))
	_ = pinUserSetCmd.Flags().Set("so-pin", "so")
	_ = pinUserSetCmd.Flags().Set("new-pin", "user")
	code := captureExit(t, func() {
		pinUserSetCmd.Run(pinUserSetCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPinUserChangeCmd_SuccessAndError(t *testing.T) {
	resetCmdFlags(t, pinUserChangeCmd)
	t.Cleanup(func() { resetCmdFlags(t, pinUserChangeCmd) })
	mock := &mockPINClient{}
	withGlobalConfig(t, newPINConfig(mock))
	_ = pinUserChangeCmd.Flags().Set("current-pin", "old")
	_ = pinUserChangeCmd.Flags().Set("new-pin", "new")
	captureStdout(t, func() {
		pinUserChangeCmd.Run(pinUserChangeCmd, nil)
	})
	if mock.gotChangeUserReq == nil || mock.gotChangeUserReq.NewUserPIN != "new" {
		t.Errorf("ChangeUserPIN request mismatch: %+v", mock.gotChangeUserReq)
	}

	resetCmdFlags(t, pinUserChangeCmd)
	withGlobalConfig(t, newPINConfig(&mockPINClient{changeUserErr: errPinRunBoom}))
	_ = pinUserChangeCmd.Flags().Set("current-pin", "old")
	_ = pinUserChangeCmd.Flags().Set("new-pin", "new")
	code := captureExit(t, func() {
		pinUserChangeCmd.Run(pinUserChangeCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPinUserVerifyCmd_SuccessAndError(t *testing.T) {
	resetCmdFlags(t, pinUserVerifyCmd)
	t.Cleanup(func() { resetCmdFlags(t, pinUserVerifyCmd) })
	mock := &mockPINClient{}
	withGlobalConfig(t, newPINConfig(mock))
	_ = pinUserVerifyCmd.Flags().Set("pin", "123456")
	captureStdout(t, func() {
		pinUserVerifyCmd.Run(pinUserVerifyCmd, nil)
	})
	if mock.gotVerifyUserReq == nil || mock.gotVerifyUserReq.UserPIN != "123456" {
		t.Errorf("VerifyUserPIN request mismatch: %+v", mock.gotVerifyUserReq)
	}

	resetCmdFlags(t, pinUserVerifyCmd)
	withGlobalConfig(t, newPINConfig(&mockPINClient{verifyUserErr: errPinRunBoom}))
	_ = pinUserVerifyCmd.Flags().Set("pin", "123456")
	code := captureExit(t, func() {
		pinUserVerifyCmd.Run(pinUserVerifyCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPinLockoutCmd_SuccessAndError(t *testing.T) {
	withGlobalConfig(t, newPINConfig(&mockPINClient{lockoutResp: &transport.LockoutStatusResponse{
		FailedAttempts: 2, MaxAttempts: 5, IsLocked: false,
	}}))
	out := captureStdout(t, func() {
		pinLockoutCmd.Run(pinLockoutCmd, nil)
	})
	if !strings.Contains(out, "Failed Attempts") {
		t.Errorf("expected lockout status output, got %q", out)
	}

	withGlobalConfig(t, newPINConfig(&mockPINClient{lockoutErr: errPinRunBoom}))
	code := captureExit(t, func() {
		pinLockoutCmd.Run(pinLockoutCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPinLockoutResetCmd_SuccessAndError(t *testing.T) {
	resetCmdFlags(t, pinLockoutResetCmd)
	t.Cleanup(func() { resetCmdFlags(t, pinLockoutResetCmd) })
	mock := &mockPINClient{}
	withGlobalConfig(t, newPINConfig(mock))
	_ = pinLockoutResetCmd.Flags().Set("so-pin", "so")
	captureStdout(t, func() {
		pinLockoutResetCmd.Run(pinLockoutResetCmd, nil)
	})
	if mock.gotResetReq == nil || mock.gotResetReq.SOPIN != "so" {
		t.Errorf("ResetLockout request mismatch: %+v", mock.gotResetReq)
	}

	resetCmdFlags(t, pinLockoutResetCmd)
	withGlobalConfig(t, newPINConfig(&mockPINClient{resetErr: errPinRunBoom}))
	_ = pinLockoutResetCmd.Flags().Set("so-pin", "so")
	code := captureExit(t, func() {
		pinLockoutResetCmd.Run(pinLockoutResetCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}
