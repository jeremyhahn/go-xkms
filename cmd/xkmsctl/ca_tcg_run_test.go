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

// ca_tcg_run_test.go exercises the "xkmsctl ca tcg" command tree's Run
// closures (issue-ek, issue-ak, sign-csr, enroll), which are thin anonymous
// cobra closures (getConfig + NewPrinter + delegate) not otherwise reached
// by ca_tcg_test.go's named-function tests.
package main

import (
	"testing"
)

func TestCATCGIssueEKCmd_Run(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	oldEKPub := tcgEKPubFile
	tcgEKPubFile = ""
	defer func() { tcgEKPubFile = oldEKPub }()

	code := captureExit(t, func() {
		caTCGIssueEKCmd.Run(caTCGIssueEKCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCATCGIssueAKCmd_Run(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	oldPub := tcgPubFile
	tcgPubFile = ""
	defer func() { tcgPubFile = oldPub }()

	code := captureExit(t, func() {
		caTCGIssueAKCmd.Run(caTCGIssueAKCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCATCGSignCSRCmd_Run(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	oldCSR := tcgCSRFile
	tcgCSRFile = ""
	defer func() { tcgCSRFile = oldCSR }()

	code := captureExit(t, func() {
		caTCGSignCSRCmd.Run(caTCGSignCSRCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCATCGEnrollCmd_Run(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	oldPacked := tcgPackedCSR
	tcgPackedCSR = ""
	defer func() { tcgPackedCSR = oldPacked }()

	code := captureExit(t, func() {
		caTCGEnrollCmd.Run(caTCGEnrollCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}
