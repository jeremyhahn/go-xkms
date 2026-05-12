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

//go:build integration && linux && yubikey

// Package fido2 holds YubiKey FIDO2 integration tests.
//
// STATUS: PLACEHOLDER — requires xkey CLI feature work before tests can run.
//
// The xkey fido2 command (xkey/cmd/xkey/cmd/fido2.go) is a *virtual* CTAP2
// authenticator built on top of UHID. Its --backend flag accepts only
// 'software', 'tpm2', or 'phone' — there is no pass-through to a physical
// YubiKey HID FIDO2 interface.
//
// A meaningful YubiKey FIDO2 test requires one of:
//
//  1. A new xkey subcommand group (e.g., 'xkey fido2 yubikey info | change-pin |
//     reset') that wraps ykman fido or issues CTAP2 HID reports directly to
//     the YubiKey.
//  2. A --backend yubikey flag on a new non-daemon fido2 tool that executes
//     one-shot CTAP2 commands against the token.
//
// Until that feature lands, every test in this file calls t.Skip. This keeps
// the YubiKey rollup Makefile target green and preserves a clear forward
// reference for the feature work.
//
// Specifically NOT covered here:
//   - WebAuthn / browser credential flows (requires a browser and RP)
//   - Credential creation/assertion (requires user presence + touch protocol)
package fido2

import (
	"os/exec"
	"testing"
)

const yubikeyFIDO2UnsupportedMsg = `xkey fido2 is a virtual CTAP2 authenticator; it has no YubiKey pass-through.
Current fido2.go --backend accepts only software/tpm2/phone. Add either
'xkey fido2 yubikey ...' subcommands or a --backend yubikey one-shot mode,
then replace this skip with real tests.
Tracking file: xkey/test/integration/fido2/yubikey_fido2_test.go`

// ykmanFIDOAvailable reports whether ykman is installed and its fido
// subcommand can talk to a present YubiKey. Retained for when the real tests
// replace the skip.
func ykmanFIDOAvailable() bool {
	return exec.Command("ykman", "fido", "info").Run() == nil
}

func TestYubiKeyFIDO2_Info(t *testing.T)      { t.Skip(yubikeyFIDO2UnsupportedMsg) }
func TestYubiKeyFIDO2_ChangePIN(t *testing.T) { t.Skip(yubikeyFIDO2UnsupportedMsg) }
func TestYubiKeyFIDO2_Reset(t *testing.T)     { t.Skip(yubikeyFIDO2UnsupportedMsg) }
