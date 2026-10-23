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

package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/usb"
)

var errC704gUSB = errors.New("usb host failure")

// c704gBinary returns an existing file to stand in for an xkey binary.
func c704gBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xkey")
	require.NoError(t, os.WriteFile(path, []byte("binary"), 0o600))
	return path
}

func TestRunUSBCreate_BuildsTheImageFromTheFlags(t *testing.T) {
	bin := c704gBinary(t)
	setUSBFlagsForTest(t, "1G", []string{bin})
	pipeStdin(t, "image-pass\nimage-pass\n")
	target := filepath.Join(t.TempDir(), "xkey.img")
	var got usb.ImageConfig
	var gotPass string
	setVar(t, &usbCreateImage, func(_ context.Context, cfg usb.ImageConfig) error {
		got = cfg
		buf, err := cfg.Passphrase.Open(t.Context())
		if err != nil {
			return err
		}
		defer buf.Destroy()
		return buf.WithBytes(func(b []byte) error {
			gotPass = string(b)
			return nil
		})
	})
	cmd, buf := newUSBTestCmd(t)

	require.NoError(t, runUSBCreate(cmd, []string{target}))

	assert.Equal(t, target, got.Path)
	assert.Equal(t, int64(1<<30), got.SizeBytes)
	assert.Equal(t, []string{bin}, got.Binaries)
	assert.Equal(t, "image-pass", gotPass)
	assert.Contains(t, buf.String(), "USB image created successfully!")
	assert.Contains(t, buf.String(), "sudo dd if="+target, "an image file gets the dd hint")
}

func TestRunUSBCreate_ReportsAnImageFailure(t *testing.T) {
	setUSBFlagsForTest(t, "1G", []string{c704gBinary(t)})
	pipeStdin(t, "image-pass\nimage-pass\n")
	setVar(t, &usbCreateImage, func(context.Context, usb.ImageConfig) error { return errC704gUSB })
	cmd, buf := newUSBTestCmd(t)

	err := runUSBCreate(cmd, []string{filepath.Join(t.TempDir(), "xkey.img")})

	requireUSBCmdError(t, err, "create_image")
	assert.ErrorIs(t, err, errC704gUSB)
	assert.NotContains(t, buf.String(), "created successfully")
}

func TestRunUSBCreate_RejectsAnEmptyPassphrase(t *testing.T) {
	setUSBFlagsForTest(t, "1G", []string{c704gBinary(t)})
	pipeStdin(t, "\n\n")
	called := false
	setVar(t, &usbCreateImage, func(context.Context, usb.ImageConfig) error {
		called = true
		return nil
	})
	cmd, _ := newUSBTestCmd(t)

	err := runUSBCreate(cmd, []string{filepath.Join(t.TempDir(), "xkey.img")})

	assert.Error(t, err)
	assert.False(t, called, "no image may be built without a passphrase")
}

func TestRunUSBStatus_ReportsTheImage(t *testing.T) {
	setVar(t, &usbStatus, func(_ context.Context, path string) (*usb.ImageStatus, error) {
		return &usb.ImageStatus{
			Path:          path,
			IsBlockDevice: true,
			TotalSize:     2 << 30,
			LUKSMounted:   true,
			Binaries:      []string{"xkey-linux-amd64"},
		}, nil
	})
	cmd, buf := newUSBTestCmd(t)

	require.NoError(t, runUSBStatus(cmd, []string{"/dev/sdz"}))

	out := buf.String()
	assert.Contains(t, out, "Block device")
	assert.Contains(t, out, "Unlocked")
	assert.Contains(t, out, "Binaries (1)")
	assert.Contains(t, out, "- xkey-linux-amd64")
}

func TestRunUSBStatus_LockedImageWithoutBinaries(t *testing.T) {
	setVar(t, &usbStatus, func(_ context.Context, path string) (*usb.ImageStatus, error) {
		return &usb.ImageStatus{Path: path}, nil
	})
	cmd, buf := newUSBTestCmd(t)

	require.NoError(t, runUSBStatus(cmd, []string{"x.img"}))

	out := buf.String()
	assert.Contains(t, out, "Image file")
	assert.Contains(t, out, "Locked")
	assert.Contains(t, out, "(not detected)")
}

func TestRunUSBStatus_ReportsAStatusFailure(t *testing.T) {
	setVar(t, &usbStatus, func(context.Context, string) (*usb.ImageStatus, error) {
		return nil, errC704gUSB
	})
	cmd, _ := newUSBTestCmd(t)

	err := runUSBStatus(cmd, []string{"x.img"})

	requireUSBCmdError(t, err, "get_status")
	assert.ErrorIs(t, err, errC704gUSB)
}

func TestRunUSBUpdate_CopiesTheBinaries(t *testing.T) {
	bin := c704gBinary(t)
	setUSBFlagsForTest(t, "", []string{bin})
	var gotPath string
	var gotBinaries []string
	setVar(t, &usbUpdateBinaries, func(_ context.Context, path string, binaries []string) error {
		gotPath, gotBinaries = path, binaries
		return nil
	})
	cmd, buf := newUSBTestCmd(t)

	require.NoError(t, runUSBUpdate(cmd, []string{"x.img"}))

	assert.Equal(t, "x.img", gotPath)
	assert.Equal(t, []string{bin}, gotBinaries)
	assert.Contains(t, buf.String(), "Binaries updated successfully!")
	assert.Contains(t, buf.String(), "- "+bin)
}

func TestRunUSBUpdate_DefaultsToTheCurrentBinary(t *testing.T) {
	setUSBFlagsForTest(t, "", nil)
	var gotBinaries []string
	setVar(t, &usbUpdateBinaries, func(_ context.Context, _ string, binaries []string) error {
		gotBinaries = binaries
		return nil
	})
	cmd, buf := newUSBTestCmd(t)

	require.NoError(t, runUSBUpdate(cmd, []string{"x.img"}))

	require.Len(t, gotBinaries, 1)
	assert.Contains(t, buf.String(), "Using current binary: "+gotBinaries[0])
}

func TestRunUSBUpdate_Failures(t *testing.T) {
	t.Run("missing binary", func(t *testing.T) {
		setUSBFlagsForTest(t, "", []string{filepath.Join(t.TempDir(), "absent")})
		cmd, _ := newUSBTestCmd(t)
		requireUSBCmdError(t, runUSBUpdate(cmd, []string{"x.img"}), "validate_binary")
	})

	t.Run("update refused", func(t *testing.T) {
		setUSBFlagsForTest(t, "", []string{c704gBinary(t)})
		setVar(t, &usbUpdateBinaries, func(context.Context, string, []string) error { return errC704gUSB })
		cmd, buf := newUSBTestCmd(t)
		err := runUSBUpdate(cmd, []string{"x.img"})
		requireUSBCmdError(t, err, "update_binaries")
		assert.ErrorIs(t, err, errC704gUSB)
		assert.NotContains(t, buf.String(), "updated successfully")
	})
}
