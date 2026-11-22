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
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/stretchr/testify/assert"
)

// testDevicePath is a synthetic device node path used by tests. It never
// exists on the host; statPath is seamed to describe it.
const testDevicePath = "/dev/xkey-test-usb0"

// savedHooks captures all package-level function variables so they
// can be restored after a test mutates them.
type savedHooks struct {
	execCommand        func(string, ...string) error
	getEUID            func() int
	luksSetupLoop      func(context.Context, string) (string, error)
	luksDetachLoop     func(context.Context, string) error
	luksFormat         func(context.Context, string, enclave.ByteAccess, luks2.FormatParams) error
	luksUnlock         func(context.Context, string, enclave.ByteAccess, string) (*dmcrypt.Mapping, error)
	luksMakeFilesystem func(context.Context, string, filesystem.Type, filesystem.MakeParams) error
	luksLock           func(context.Context, string) error
	luksIsUnlocked     func(context.Context, string) bool
	luksCheckKeyring   func() error
	readMountsFile     func() ([]byte, error)
	statPath           func(string) (os.FileInfo, error)
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
		luksCheckKeyring:   luksCheckKeyring,
		readMountsFile:     readMountsFile,
		statPath:           statPath,
	}
	// The keyring preflight is the one hook that would reach the kernel
	// from a unit test; stub it so the suite never depends on the host's
	// seccomp profile. A test that wants a failing probe sets its own.
	luksCheckKeyring = func() error { return nil }

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
		luksCheckKeyring = saved.luksCheckKeyring
		readMountsFile = saved.readMountsFile
		statPath = saved.statPath
	}
}

// mockAllCommandsSuccess sets all hooks to succeed without side effects.
func mockAllCommandsSuccess(t *testing.T) {
	t.Helper()
	execCommand = func(name string, args ...string) error { return nil }
	luksSetupLoopDevice = func(_ context.Context, file string) (string, error) { return "/dev/loop99", nil }
	luksDetachLoopDevice = func(_ context.Context, device string) error { return nil }
	luksFormat = func(context.Context, string, enclave.ByteAccess, luks2.FormatParams) error { return nil }
	luksUnlock = func(_ context.Context, _ string, _ enclave.ByteAccess, name string) (*dmcrypt.Mapping, error) {
		return &dmcrypt.Mapping{Name: name}, nil
	}
	luksMakeFilesystem = func(context.Context, string, filesystem.Type, filesystem.MakeParams) error { return nil }
	luksLock = func(_ context.Context, name string) error { return nil }
	luksIsUnlocked = func(_ context.Context, name string) bool { return false }
	luksCheckKeyring = func() error { return nil }
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

// fakeFileInfo is a synthetic os.FileInfo used to describe a device node
// without requiring a real device to exist on the host.
type fakeFileInfo struct {
	name string
	mode os.FileMode
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

// mockDeviceNode makes statPath report path as a character/block device
// node so IsBlockDevice returns true without touching the host.
func mockDeviceNode(path string) {
	statPath = func(p string) (os.FileInfo, error) {
		if p == path {
			return fakeFileInfo{name: p, mode: os.ModeDevice | 0o660}, nil
		}
		return nil, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
	}
}
