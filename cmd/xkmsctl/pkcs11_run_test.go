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

// pkcs11_run_test.go closes additional deterministic error branches in
// pkcs11.go that pkcs11_test.go's --help/missing-flag tests don't reach.
//
// IMPORTANT: this package builds WITHOUT the `pkcs11` build tag (per the
// project's standard unit-test invocation), so sdk/go/pkcs11/manager falls
// back to pkg/pkcs11/manager's stubManager, whose every operation
// (RegisterModule, InitializeToken, Connect, Disconnect) deterministically
// returns manager.ErrPKCS11Disabled regardless of host state. That makes the
// "operation failed" branches exercised here fully deterministic and
// hardware-free. The corresponding SUCCESS branches (a real module
// registers/connects/initializes) can only be exercised by building with
// `-tags pkcs11` against a real or SoftHSM-backed module, which is out of
// scope for this package's fast unit-test tier — see the qa-engineer /
// pkcs11-expert integration suite for that coverage.
package main

import (
	"testing"
)

func TestPKCS11RegisterCmd_ManagerError(t *testing.T) {
	cmd := pkcs11RegisterCmd
	_ = cmd.Flags().Set("module", "/opt/fake/libpkcs11.so")
	_ = cmd.Flags().Set("name", "FakeModule")
	t.Cleanup(func() {
		_ = cmd.Flags().Set("module", "")
		_ = cmd.Flags().Set("name", "")
	})

	code := captureExit(t, func() {
		cmd.Run(cmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (stub manager always errors), got %d", code)
	}
}

func TestPKCS11InitTokenCmd_ModuleIDDirect_ManagerError(t *testing.T) {
	cmd := pkcs11InitTokenCmd
	_ = cmd.Flags().Set("module-id", "pkcs11-fake")
	_ = cmd.Flags().Set("label", "TestToken")
	_ = cmd.Flags().Set("so-pin", "12345678")
	_ = cmd.Flags().Set("user-pin", "1234")
	t.Cleanup(func() {
		_ = cmd.Flags().Set("module-id", "")
		_ = cmd.Flags().Set("label", "")
		_ = cmd.Flags().Set("so-pin", "")
		_ = cmd.Flags().Set("user-pin", "")
	})

	code := captureExit(t, func() {
		cmd.Run(cmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (stub manager always errors), got %d", code)
	}
}

func TestPKCS11InitTokenCmd_ModulePath_RegisterError(t *testing.T) {
	cmd := pkcs11InitTokenCmd
	_ = cmd.Flags().Set("module", "/opt/fake/libpkcs11.so")
	_ = cmd.Flags().Set("label", "TestToken")
	_ = cmd.Flags().Set("so-pin", "12345678")
	_ = cmd.Flags().Set("user-pin", "1234")
	t.Cleanup(func() {
		_ = cmd.Flags().Set("module", "")
		_ = cmd.Flags().Set("label", "")
		_ = cmd.Flags().Set("so-pin", "")
		_ = cmd.Flags().Set("user-pin", "")
	})

	code := captureExit(t, func() {
		cmd.Run(cmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (stub manager always errors on register), got %d", code)
	}
}

func TestPKCS11ConnectCmd_ModuleIDDirect_ManagerError(t *testing.T) {
	cmd := pkcs11ConnectCmd
	_ = cmd.Flags().Set("module-id", "pkcs11-fake")
	_ = cmd.Flags().Set("pin", "1234")
	t.Cleanup(func() {
		_ = cmd.Flags().Set("module-id", "")
		_ = cmd.Flags().Set("pin", "")
	})

	code := captureExit(t, func() {
		cmd.Run(cmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (stub manager always errors), got %d", code)
	}
}

func TestPKCS11ConnectCmd_ModulePath_RegisterError(t *testing.T) {
	cmd := pkcs11ConnectCmd
	_ = cmd.Flags().Set("module", "/opt/fake/libpkcs11.so")
	_ = cmd.Flags().Set("pin", "1234")
	t.Cleanup(func() {
		_ = cmd.Flags().Set("module", "")
		_ = cmd.Flags().Set("pin", "")
	})

	code := captureExit(t, func() {
		cmd.Run(cmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (stub manager always errors on register), got %d", code)
	}
}

func TestPKCS11ConnectCmd_NoModuleOrModuleID(t *testing.T) {
	cmd := pkcs11ConnectCmd
	_ = cmd.Flags().Set("pin", "1234")
	t.Cleanup(func() {
		_ = cmd.Flags().Set("pin", "")
	})

	code := captureExit(t, func() {
		cmd.Run(cmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for missing --module/--module-id, got %d", code)
	}
}

func TestPKCS11DisconnectCmd_ManagerError(t *testing.T) {
	cmd := pkcs11DisconnectCmd
	_ = cmd.Flags().Set("module-id", "pkcs11-fake")
	t.Cleanup(func() {
		_ = cmd.Flags().Set("module-id", "")
	})

	code := captureExit(t, func() {
		cmd.Run(cmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (stub manager always errors), got %d", code)
	}
}

func TestPKCS11ProbeCmd_JSONFormatDirect(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "json"})
	captureStdout(t, func() {
		pkcs11ProbeCmd.Run(pkcs11ProbeCmd, nil)
	})
}

func TestPKCS11ListModulesCmd_JSONFormatDirect(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "json"})
	captureStdout(t, func() {
		pkcs11ListModulesCmd.Run(pkcs11ListModulesCmd, nil)
	})
}

func TestPKCS11ListTokensCmd_JSONFormatDirect(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "json"})
	captureStdout(t, func() {
		pkcs11ListTokensCmd.Run(pkcs11ListTokensCmd, nil)
	})
}
