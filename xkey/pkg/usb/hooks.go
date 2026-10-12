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
	"os"
	"os/exec"
	"strings"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/pkg/loop"
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

// luksSetupLoopDevice attaches a loop device to an image file and returns
// the device node path.
var luksSetupLoopDevice = attachLoopDevice

// luksDetachLoopDevice detaches the loop device at a node path.
var luksDetachLoopDevice = detachLoopDevice

// luksFormat writes a new LUKS2 header to a partition.
var luksFormat = formatVolume

// luksUnlock unlocks a LUKS2 partition and maps it under a device-mapper name.
var luksUnlock = activateVolume

// luksCheckKeyring proves the kernel keyring is usable before a partition is
// formatted and unlocked. It is the luks package's per-operation preflight, so
// a USB provisioning run gets the same refusal, with the same cause and remedy,
// that a volume unlock would.
var luksCheckKeyring = luks.EnsureKeyringAvailable

// luksMakeFilesystem creates a filesystem on an unlocked LUKS mapping.
var luksMakeFilesystem = filesystem.Make

// luksLock removes a LUKS2 device-mapper mapping.
var luksLock = dmcrypt.Deactivate

// luksIsUnlocked reports whether a LUKS2 device-mapper mapping exists.
var luksIsUnlocked = mappingExists

// attachLoopDevice attaches a loop device to file and returns its node path.
func attachLoopDevice(ctx context.Context, file string) (string, error) {
	dev, err := loop.Attach(ctx, file)
	if err != nil {
		return "", err
	}
	return dev.Path(), nil
}

// detachLoopDevice detaches the loop device at path. A detach the kernel
// deferred because something still holds the device is a success: it
// completes when the holder goes.
func detachLoopDevice(ctx context.Context, path string) error {
	dev, err := loop.Lookup(ctx, path)
	if err != nil {
		return err
	}
	_, err = dev.Detach(ctx)
	return err
}

// formatVolume writes a new LUKS2 header to device, protected by pass.
func formatVolume(ctx context.Context, device string, pass *enclave.MemoryEnclave, params luks2.FormatParams) error {
	volume, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	return errors.Join(volume.Format(ctx, pass, params), volume.Close())
}

// activateVolume unlocks the LUKS2 container on device with pass and maps
// it under name. The volume key never leaves go-luks2: it is destroyed as
// soon as the mapping exists, and a mapping whose volume could not be
// released is torn down again rather than reported half-done.
func activateVolume(ctx context.Context, device string, pass *enclave.MemoryEnclave, name string) (*dmcrypt.Mapping, error) {
	volume, err := luks2.Open(ctx, device)
	if err != nil {
		return nil, err
	}
	key, err := volume.Unlock(ctx, pass)
	if err != nil {
		return nil, errors.Join(err, volume.Close())
	}
	mapping, err := dmcrypt.Activate(ctx, volume, key, name)
	key.Destroy()
	if err != nil {
		return nil, errors.Join(err, volume.Close())
	}
	if err := volume.Close(); err != nil {
		return nil, errors.Join(err, dmcrypt.Deactivate(ctx, name))
	}
	return mapping, nil
}

// mappingExists reports whether device-mapper has a live target named name.
// A lookup that fails for any reason reports false.
func mappingExists(ctx context.Context, name string) bool {
	_, err := dmcrypt.Lookup(ctx, name)
	return err == nil
}

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
