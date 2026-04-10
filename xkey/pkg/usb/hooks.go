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
var getEUID = func() int {
	return os.Geteuid()
}

// luksSetupLoopDevice sets up a loop device for an image file.
var luksSetupLoopDevice = func(file string) (string, error) {
	return luks2.SetupLoopDevice(file)
}

// luksDetachLoopDevice detaches a loop device.
var luksDetachLoopDevice = func(device string) error {
	return luks2.DetachLoopDevice(device)
}

// luksFormat formats a partition as LUKS2.
var luksFormat = func(opts luks2.FormatOptions) error {
	return luks2.Format(opts)
}

// luksUnlock unlocks a LUKS2 partition.
var luksUnlock = func(device string, passphrase []byte, name string) error {
	return luks2.Unlock(device, passphrase, name)
}

// luksMakeFilesystem creates a filesystem on an unlocked LUKS device.
var luksMakeFilesystem = func(device, fstype, label string) error {
	return luks2.MakeFilesystem(device, fstype, label)
}

// luksLock locks a LUKS2 partition.
var luksLock = func(name string) error {
	return luks2.Lock(name)
}

// luksIsUnlocked checks if a LUKS2 partition is unlocked.
var luksIsUnlocked = func(name string) bool {
	return luks2.IsUnlocked(name)
}

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
