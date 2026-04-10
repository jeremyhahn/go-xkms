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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/stretchr/testify/assert"
)

// savedHooks captures all package-level function variables so they
// can be restored after a test mutates them.
type savedHooks struct {
	execCommand        func(string, ...string) error
	getEUID            func() int
	luksSetupLoop      func(string) (string, error)
	luksDetachLoop     func(string) error
	luksFormat         func(luks2.FormatOptions) error
	luksUnlock         func(string, []byte, string) error
	luksMakeFilesystem func(string, string, string) error
	luksLock           func(string) error
	luksIsUnlocked     func(string) bool
	readMountsFile     func() ([]byte, error)
}

// saveHooks captures the current state of all hooks and returns a
// restore function. Call the restore function in a defer or cleanup.
func saveHooks(t *testing.T) func() {
	t.Helper()
	saved := savedHooks{
		execCommand:        execCommand,
		getEUID:            getEUID,
		luksSetupLoop:      luksSetupLoopDevice,
		luksDetachLoop:     luksDetachLoopDevice,
		luksFormat:         luksFormat,
		luksUnlock:         luksUnlock,
		luksMakeFilesystem: luksMakeFilesystem,
		luksLock:           luksLock,
		luksIsUnlocked:     luksIsUnlocked,
		readMountsFile:     readMountsFile,
	}
	return func() {
		execCommand = saved.execCommand
		getEUID = saved.getEUID
		luksSetupLoopDevice = saved.luksSetupLoop
		luksDetachLoopDevice = saved.luksDetachLoop
		luksFormat = saved.luksFormat
		luksUnlock = saved.luksUnlock
		luksMakeFilesystem = saved.luksMakeFilesystem
		luksLock = saved.luksLock
		luksIsUnlocked = saved.luksIsUnlocked
		readMountsFile = saved.readMountsFile
	}
}

// mockAllCommandsSuccess sets all hooks to succeed without side effects.
func mockAllCommandsSuccess(t *testing.T) {
	t.Helper()
	execCommand = func(name string, args ...string) error { return nil }
	luksSetupLoopDevice = func(file string) (string, error) { return "/dev/loop99", nil }
	luksDetachLoopDevice = func(device string) error { return nil }
	luksFormat = func(opts luks2.FormatOptions) error { return nil }
	luksUnlock = func(device string, passphrase []byte, name string) error { return nil }
	luksMakeFilesystem = func(device, fstype, label string) error { return nil }
	luksLock = func(name string) error { return nil }
	luksIsUnlocked = func(name string) bool { return false }
	readMountsFile = func() ([]byte, error) { return []byte(""), nil }
}

// mockRootUser sets getEUID to return 0 (root).
func mockRootUser() {
	getEUID = func() int { return 0 }
}

// mockNonRootUser sets getEUID to return 1000 (non-root).
func mockNonRootUser() {
	getEUID = func() int { return 1000 }
}

// TestCommandError_Error verifies the CommandError formatted output.
func TestCommandError_Error(t *testing.T) {
	err := &CommandError{
		Name:   "sgdisk",
		Args:   []string{"--zap-all", "/dev/sdb"},
		Output: "device busy",
		Err:    errors.New("exit status 1"),
	}
	expected := "sgdisk --zap-all /dev/sdb: exit status 1: device busy"
	assert.Equal(t, expected, err.Error())
}

// TestCommandError_Unwrap verifies the CommandError unwraps correctly.
func TestCommandError_Unwrap(t *testing.T) {
	underlying := errors.New("exit status 1")
	err := &CommandError{
		Name: "sgdisk",
		Args: []string{"--zap-all"},
		Err:  underlying,
	}
	assert.Equal(t, underlying, err.Unwrap())
	assert.True(t, errors.Is(err, underlying))
}

// TestCommandError_NoArgs verifies CommandError formats without args.
func TestCommandError_NoArgs(t *testing.T) {
	err := &CommandError{
		Name:   "true",
		Args:   nil,
		Output: "",
		Err:    errors.New("fail"),
	}
	assert.Equal(t, "true : fail: ", err.Error())
}
