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

// ca_run_test.go exercises the "xkmsctl ca" command tree's Run closures
// (bundle, certificate, sign-csr, issue, revoke, crl, status), which are
// thin anonymous cobra closures (getConfig + NewPrinter + delegate) not
// otherwise reached by ca_test.go's named-function tests.
package main

import (
	"testing"
)

func TestCABundleCmd_Run(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		caBundleCmd.Run(caBundleCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCACertificateCmd_Run(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		caCertificateCmd.Run(caCertificateCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCASignCSRCmd_Run(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	old := caCSRFile
	caCSRFile = ""
	defer func() { caCSRFile = old }()

	code := captureExit(t, func() {
		caSignCSRCmd.Run(caSignCSRCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCAIssueCmd_Run(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	old := caCommonName
	caCommonName = ""
	defer func() { caCommonName = old }()

	code := captureExit(t, func() {
		caIssueCmd.Run(caIssueCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCARevokeCmd_Run(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	old := caSerial
	caSerial = ""
	defer func() { caSerial = old }()

	code := captureExit(t, func() {
		caRevokeCmd.Run(caRevokeCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCACRLCmd_Run(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		caCRLCmd.Run(caCRLCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCAStatusCmd_Run(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	old := caSerial
	caSerial = ""
	defer func() { caSerial = old }()

	code := captureExit(t, func() {
		caStatusCmd.Run(caStatusCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}
