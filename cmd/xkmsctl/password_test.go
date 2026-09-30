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

// password_test.go defines mockPasswordClient and exercises the
// "xkmsctl password" flag/argument validation paths.
package main

import (
	"context"
	"strings"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockPasswordClient is a mock client for testing password operations.
type mockPasswordClient struct {
	mockBackendsClient
	addResp    *transport.PasswordAddResponse
	addErr     error
	getResp    *transport.PasswordGetResponse
	getErr     error
	listResp   *transport.PasswordListResponse
	listErr    error
	updateErr  error
	deleteErr  error
	unlockErr  error
	lockErr    error
	statusResp *transport.PasswordStoreStatusResponse
	statusErr  error
	setModeErr error
	genResp    *transport.PasswordGenerateResponse
	genErr     error

	vaultStatusResp  *transport.PasswordVaultStatusResponse
	vaultStatusErr   error
	vaultEnrollResp  *transport.PasswordVaultEnrollResponse
	vaultEnrollErr   error
	vaultRotateResp  *transport.PasswordVaultEnrollResponse
	vaultRotateErr   error
	vaultRemoveErr   error
	vaultRecoverResp *transport.PasswordVaultEnrollResponse
	vaultRecoverErr  error

	// Captured requests for assertion.
	gotAddReq     *transport.PasswordAddRequest
	gotGetReq     *transport.PasswordGetRequest
	gotListReq    *transport.PasswordListRequest
	gotUpdateReq  *transport.PasswordUpdateRequest
	gotDeleteReq  *transport.PasswordDeleteRequest
	gotUnlockReq  *transport.PasswordStoreUnlockRequest
	gotSetModeReq *transport.PasswordStoreSetAccessModeRequest
	gotGenReq     *transport.PasswordGenerateRequest
	gotEnrollReq  *transport.PasswordVaultEnrollRequest
	gotRotateReq  *transport.PasswordVaultRotateRequest
	gotRemoveReq  *transport.PasswordVaultRemoveFactorRequest
	gotRecoverReq *transport.PasswordVaultRecoverRequest
	lockCalled    bool
}

func (m *mockPasswordClient) PasswordAdd(_ context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	m.gotAddReq = req
	return m.addResp, m.addErr
}

func (m *mockPasswordClient) PasswordGet(_ context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	m.gotGetReq = req
	return m.getResp, m.getErr
}

func (m *mockPasswordClient) PasswordList(_ context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	m.gotListReq = req
	return m.listResp, m.listErr
}

func (m *mockPasswordClient) PasswordUpdate(_ context.Context, req *transport.PasswordUpdateRequest) error {
	m.gotUpdateReq = req
	return m.updateErr
}

func (m *mockPasswordClient) PasswordDelete(_ context.Context, req *transport.PasswordDeleteRequest) error {
	m.gotDeleteReq = req
	return m.deleteErr
}

func (m *mockPasswordClient) PasswordStoreUnlock(_ context.Context, req *transport.PasswordStoreUnlockRequest) error {
	m.gotUnlockReq = req
	return m.unlockErr
}

func (m *mockPasswordClient) PasswordStoreLock(_ context.Context) error {
	m.lockCalled = true
	return m.lockErr
}

func (m *mockPasswordClient) PasswordStoreStatus(_ context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return m.statusResp, m.statusErr
}

func (m *mockPasswordClient) PasswordStoreSetAccessMode(_ context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	m.gotSetModeReq = req
	return m.setModeErr
}

func (m *mockPasswordClient) PasswordGenerate(_ context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	m.gotGenReq = req
	return m.genResp, m.genErr
}

func (m *mockPasswordClient) PasswordVaultStatus(_ context.Context) (*transport.PasswordVaultStatusResponse, error) {
	return m.vaultStatusResp, m.vaultStatusErr
}

func (m *mockPasswordClient) PasswordVaultEnroll(_ context.Context, req *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	m.gotEnrollReq = req
	return m.vaultEnrollResp, m.vaultEnrollErr
}

func (m *mockPasswordClient) PasswordVaultRotate(_ context.Context, req *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	m.gotRotateReq = req
	return m.vaultRotateResp, m.vaultRotateErr
}

func (m *mockPasswordClient) PasswordVaultRemoveFactor(_ context.Context, req *transport.PasswordVaultRemoveFactorRequest) error {
	m.gotRemoveReq = req
	return m.vaultRemoveErr
}

func (m *mockPasswordClient) PasswordVaultRecover(_ context.Context, req *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	m.gotRecoverReq = req
	return m.vaultRecoverResp, m.vaultRecoverErr
}

func newPasswordConfig(mock *mockPasswordClient) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func TestPasswordAddCmd_EmptySecret(t *testing.T) {
	resetCmdFlags(t, passwordAddCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordAddCmd) })
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{}))
	withPromptInput(t, "\n")

	code := captureExit(t, func() {
		passwordAddCmd.Run(passwordAddCmd, []string{"github"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for empty secret, got %d", code)
	}
}

func TestPasswordUpdateCmd_NoFields(t *testing.T) {
	resetCmdFlags(t, passwordUpdateCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordUpdateCmd) })
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{}))

	code := captureExit(t, func() {
		passwordUpdateCmd.Run(passwordUpdateCmd, []string{"id-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for no update fields, got %d", code)
	}
}

func TestPasswordUpdateCmd_EmptyPromptedPassword(t *testing.T) {
	resetCmdFlags(t, passwordUpdateCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordUpdateCmd) })
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{}))
	withPromptInput(t, "\n")
	_ = passwordUpdateCmd.Flags().Set("password", "")

	code := captureExit(t, func() {
		passwordUpdateCmd.Run(passwordUpdateCmd, []string{"id-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for empty prompted password, got %d", code)
	}
}

func TestPasswordAccessModeCmd_MissingMode(t *testing.T) {
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{}))

	code := captureExit(t, func() {
		passwordAccessModeCmd.Run(passwordAccessModeCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for missing mode, got %d", code)
	}
}

func TestPasswordAccessModeCmd_InvalidMode(t *testing.T) {
	withGlobalConfig(t, newPasswordConfig(&mockPasswordClient{}))

	code := captureExit(t, func() {
		passwordAccessModeCmd.Run(passwordAccessModeCmd, []string{"bogus"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for invalid mode, got %d", code)
	}
}

// "password get" never had a working --decrypt/--user-pin: every store
// reachable through the server returns an entry exactly as stored, so the
// flags could never do what their help text promised (#1061). Both must now
// be unknown flags rather than silently accepted and ignored.
func TestPasswordGetCmd_DecryptFlagRemoved(t *testing.T) {
	resetCmdFlags(t, passwordGetCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordGetCmd) })

	err := passwordGetCmd.Flags().Parse([]string{"--decrypt=true"})
	if err == nil {
		t.Fatal("expected an unknown-flag error for --decrypt, got nil")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("expected an unknown-flag error, got %q", err)
	}
}

func TestPasswordGetCmd_UserPINFlagRemoved(t *testing.T) {
	resetCmdFlags(t, passwordGetCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordGetCmd) })

	err := passwordGetCmd.Flags().Parse([]string{"--user-pin=1234"})
	if err == nil {
		t.Fatal("expected an unknown-flag error for --user-pin, got nil")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("expected an unknown-flag error, got %q", err)
	}
}

func TestPasswordCmd_Registered(t *testing.T) {
	for _, verb := range []string{
		"add", "get", "list", "update", "delete",
		"unlock", "lock", "status", "access-mode", "generate", "vault",
	} {
		if _, _, err := rootCmd.Find([]string{"password", verb}); err != nil {
			t.Errorf("password %s missing: %v", verb, err)
		}
	}
}
