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

	// Captured requests for assertion.
	gotAddReq     *transport.PasswordAddRequest
	gotGetReq     *transport.PasswordGetRequest
	gotListReq    *transport.PasswordListRequest
	gotUpdateReq  *transport.PasswordUpdateRequest
	gotDeleteReq  *transport.PasswordDeleteRequest
	gotUnlockReq  *transport.PasswordStoreUnlockRequest
	gotSetModeReq *transport.PasswordStoreSetAccessModeRequest
	gotGenReq     *transport.PasswordGenerateRequest
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

func TestPasswordCmd_Registered(t *testing.T) {
	for _, verb := range []string{
		"add", "get", "list", "update", "delete",
		"unlock", "lock", "status", "access-mode", "generate",
	} {
		if _, _, err := rootCmd.Find([]string{"password", verb}); err != nil {
			t.Errorf("password %s missing: %v", verb, err)
		}
	}
}
