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

// user_ext_run_test.go exercises the "xkmsctl user update" and
// "xkmsctl user bind-cert" subcommands.
package main

import (
	"context"
	"errors"
	"testing"
)

var errUserExtBoom = errors.New("boom")

// mockUserExtClient adds a configurable BindUserCert error on top of the user
// mock (the base BindUserCert always succeeds, so it cannot exercise the
// error path).
type mockUserExtClient struct {
	mockUserClient
	bindErr error

	gotBindUsername   string
	gotBindThumbprint string
}

func (m *mockUserExtClient) BindUserCert(_ context.Context, username, thumbprint string, _ int64) error {
	m.gotBindUsername = username
	m.gotBindThumbprint = thumbprint
	return m.bindErr
}

func TestUserUpdateCmd_RequiresExactlyOneFlag(t *testing.T) {
	resetCmdFlags(t, userUpdateCmd)
	t.Cleanup(func() { resetCmdFlags(t, userUpdateCmd) })
	withGlobalConfig(t, newUserTestConfig("text", &mockUserClient{}))

	// Neither flag set: enable == disable == false → conflict error.
	code := captureExit(t, func() {
		userUpdateCmd.Run(userUpdateCmd, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 with no flags, got %d", code)
	}
}

func TestUserUpdateCmd_DisableError(t *testing.T) {
	resetCmdFlags(t, userUpdateCmd)
	t.Cleanup(func() { resetCmdFlags(t, userUpdateCmd) })
	withGlobalConfig(t, newUserTestConfig("text", &mockUserClient{disableUserErr: errUserExtBoom}))
	_ = userUpdateCmd.Flags().Set("disable", "true")

	code := captureExit(t, func() {
		userUpdateCmd.Run(userUpdateCmd, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 on disable failure, got %d", code)
	}
}

func TestUserBindCertCmd_RequiresSource(t *testing.T) {
	resetCmdFlags(t, userBindCertCmd)
	t.Cleanup(func() { resetCmdFlags(t, userBindCertCmd) })
	withGlobalConfig(t, newUserTestConfig("text", &mockUserClient{}))

	// Neither --thumbprint nor --cert-file: source-required error.
	code := captureExit(t, func() {
		userBindCertCmd.Run(userBindCertCmd, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 without a cert source, got %d", code)
	}
}
