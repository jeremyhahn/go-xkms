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

//go:build integration && yubikey

// Package oath holds YubiKey OATH integration tests.
//
// STATUS: PLACEHOLDER — requires xkey CLI feature work before tests can run.
//
// The xkey oath command (xkey/cmd/xkey/cmd/oath.go) currently stores all
// credentials via oath.NewFileStore(storePath) and has no command-line surface
// for talking to a YubiKey OATH applet over CCID. A meaningful YubiKey OATH
// test requires one of:
//
//  1. A new --backend yubikey flag that routes through ykman or a native
//     CCID/APDU OATH client.
//  2. A direct "xkey oath yubikey ..." subcommand group that issues OATH
//     applet commands (PUT, CALCULATE, DELETE, LIST, RESET) to the token.
//
// Until that feature lands, every test in this file calls t.Skip with a
// reference to this file so CI does not silently drop coverage.
package oath

import (
	"os"
	"os/exec"
	"testing"
)

const ykmanBinaryPath = "/usr/bin/ykman"

const yubikeyOATHUnsupportedMsg = `xkey oath has no YubiKey OATH applet backend.
Current oath.go routes every command through oath.NewFileStore. Add a
--backend yubikey flag (or 'xkey oath yubikey ...' subcommands) that drives
the CCID OATH applet, then replace this skip with real tests.
Tracking file: xkey/test/integration/oath/yubikey_oath_test.go`

// ykmanAvailable reports whether ykman is installed and its oath subcommand
// can talk to a present YubiKey. Kept as a helper so the future real tests
// only need to delete the skip and flip this into a gate.
func ykmanAvailable() bool {
	if _, err := os.Stat(ykmanBinaryPath); err != nil {
		return false
	}
	if err := exec.Command(ykmanBinaryPath, "oath", "info").Run(); err != nil {
		return false
	}
	return true
}

func TestYubiKeyOATH_AddTOTP(t *testing.T)      { t.Skip(yubikeyOATHUnsupportedMsg) }
func TestYubiKeyOATH_AddHOTP(t *testing.T)      { t.Skip(yubikeyOATHUnsupportedMsg) }
func TestYubiKeyOATH_GenerateTOTP(t *testing.T) { t.Skip(yubikeyOATHUnsupportedMsg) }
func TestYubiKeyOATH_GenerateHOTP(t *testing.T) { t.Skip(yubikeyOATHUnsupportedMsg) }
func TestYubiKeyOATH_ListEmpty(t *testing.T)    { t.Skip(yubikeyOATHUnsupportedMsg) }
func TestYubiKeyOATH_Remove(t *testing.T)       { t.Skip(yubikeyOATHUnsupportedMsg) }
func TestYubiKeyOATH_DuplicateAdd(t *testing.T) { t.Skip(yubikeyOATHUnsupportedMsg) }
