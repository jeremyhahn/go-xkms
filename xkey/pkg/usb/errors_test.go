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

	"github.com/stretchr/testify/assert"
)

func TestUSBError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *USBError
		expected string
	}{
		{
			name: "with path",
			err: &USBError{
				Operation: "format",
				Path:      "/dev/sdb1",
				Err:       errors.New("device busy"),
			},
			expected: "usb: format failed for /dev/sdb1: device busy",
		},
		{
			name: "without path",
			err: &USBError{
				Operation: "scan",
				Err:       errors.New("permission denied"),
			},
			expected: "usb: scan failed: permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestUSBError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying cause")
	err := &USBError{
		Operation: "test",
		Err:       underlying,
	}

	assert.Equal(t, underlying, err.Unwrap())
	assert.True(t, errors.Is(err, underlying))
}

func TestUSBError_ErrorsAs(t *testing.T) {
	underlying := errors.New("base error")
	err := &USBError{
		Operation: "partition",
		Path:      "/dev/sdb",
		Err:       underlying,
	}

	var target *USBError
	assert.True(t, errors.As(err, &target))
	assert.Equal(t, "partition", target.Operation)
	assert.Equal(t, "/dev/sdb", target.Path)
}

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"DeviceNotFound", ErrDeviceNotFound, "usb: device or image not found"},
		{"DeviceBusy", ErrDeviceBusy, "usb: device is busy"},
		{"ImageExists", ErrImageExists, "usb: image already exists"},
		{"ImageNotFound", ErrImageNotFound, "usb: image not found"},
		{"InvalidSize", ErrInvalidSize, "usb: invalid size"},
		{"PartitionFailed", ErrPartitionFailed, "usb: partitioning failed"},
		{"FormatFailed", ErrFormatFailed, "usb: format failed"},
		{"MountFailed", ErrMountFailed, "usb: mount failed"},
		{"UnmountFailed", ErrUnmountFailed, "usb: unmount failed"},
		{"PermissionDenied", ErrPermissionDenied, "usb: permission denied (requires root)"},
		{"SystemDisk", ErrSystemDisk, "usb: device appears to be a system disk"},
		{"CopyFailed", ErrCopyFailed, "usb: file copy failed"},
		{"LoopSetupFailed", ErrLoopSetupFailed, "usb: loop device setup failed"},
		{"BinaryNotFound", ErrBinaryNotFound, "usb: binary not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}

func TestSentinelErrors_AreDistinct(t *testing.T) {
	errs := []error{
		ErrDeviceNotFound,
		ErrDeviceBusy,
		ErrImageExists,
		ErrImageNotFound,
		ErrInvalidSize,
		ErrPartitionFailed,
		ErrFormatFailed,
		ErrMountFailed,
		ErrUnmountFailed,
		ErrPermissionDenied,
		ErrSystemDisk,
		ErrCopyFailed,
		ErrLoopSetupFailed,
		ErrBinaryNotFound,
	}

	for i := 0; i < len(errs); i++ {
		for j := i + 1; j < len(errs); j++ {
			assert.NotEqual(t, errs[i].Error(), errs[j].Error(),
				"errors at index %d and %d should be distinct", i, j)
		}
	}
}

func TestUSBError_WrapsErrDeviceNotFound(t *testing.T) {
	err := &USBError{
		Operation: "validate",
		Path:      "/dev/sdc",
		Err:       ErrDeviceNotFound,
	}

	assert.True(t, errors.Is(err, ErrDeviceNotFound))
	assert.Contains(t, err.Error(), "/dev/sdc")
}
