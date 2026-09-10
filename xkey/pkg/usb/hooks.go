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

package usb

import (
	"os"
	"os/exec"
	"strings"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
)

// Package-level function variables allow tests to replace external
// dependencies (commands, luks2, privilege checks) without modifying
// the host system or requiring root.

// execCommand runs an external command and returns an error on failure.
// Tests replace this to simulate command success or failure.
var execCommand = func(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &CommandError{
			Name:   name,
			Args:   args,
			Output: strings.TrimSpace(string(output)),
			Err:    err,
		}
	}
	return nil
}

// getEUID returns the effective user ID. Tests replace this to
// simulate root or non-root execution.
var getEUID = os.Geteuid

// luksSetupLoopDevice sets up a loop device for an image file.
var luksSetupLoopDevice = luks2.SetupLoopDevice

// luksDetachLoopDevice detaches a loop device.
var luksDetachLoopDevice = luks2.DetachLoopDevice

// luksFormat formats a partition as LUKS2.
var luksFormat = luks2.Format

// luksUnlock unlocks a LUKS2 partition.
var luksUnlock = luks2.Unlock

// luksCheckKeyring proves the kernel keyring is usable before a partition is
// formatted and unlocked. It is the luks package's per-operation preflight, so
// a USB provisioning run gets the same refusal, with the same cause and remedy,
// that a volume unlock would.
var luksCheckKeyring = luks.EnsureKeyringAvailable

// luksMakeFilesystem creates a filesystem on an unlocked LUKS device.
var luksMakeFilesystem = luks2.MakeFilesystem

// luksLock locks a LUKS2 partition.
var luksLock = luks2.Lock

// luksIsUnlocked checks if a LUKS2 partition is unlocked.
var luksIsUnlocked = luks2.IsUnlocked

// statPath stats a filesystem path. Tests replace this to describe a
// synthetic device node without depending on a real device existing on
// the host.
var statPath = os.Stat

// readMountsFile reads the mount information file. Tests replace
// this to provide synthetic mount data without reading /proc/mounts.
var readMountsFile = func() ([]byte, error) {
	return os.ReadFile("/proc/mounts")
}

// CommandError represents a failed external command execution.
type CommandError struct {
	Name   string
	Args   []string
	Output string
	Err    error
}

// Error returns the formatted error message.
func (e *CommandError) Error() string {
	return e.Name + " " + strings.Join(e.Args, " ") + ": " + e.Err.Error() + ": " + e.Output
}

// Unwrap returns the underlying error.
func (e *CommandError) Unwrap() error {
	return e.Err
}
