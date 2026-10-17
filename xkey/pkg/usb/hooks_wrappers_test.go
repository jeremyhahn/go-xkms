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
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/stretchr/testify/assert"
)

// The kernel wrappers are exercised end to end by the integration suite.
// These tests cover the path where the target does not exist: each wrapper
// must fail before it reaches a loop or device-mapper ioctl, so nothing on
// the host changes.

func TestDetachLoopDevice_MissingDevice(t *testing.T) {
	err := detachLoopDevice(t.Context(), filepath.Join(t.TempDir(), "loop-absent"))
	assert.Error(t, err)
}

func TestFormatVolume_MissingDevice(t *testing.T) {
	err := formatVolume(t.Context(), filepath.Join(t.TempDir(), "disk-absent"), nil, luks2.FormatParams{})
	assert.Error(t, err)
}

func TestActivateVolume_MissingDevice(t *testing.T) {
	mapping, err := activateVolume(t.Context(), filepath.Join(t.TempDir(), "disk-absent"), nil, "xkey-test-absent")
	assert.Error(t, err)
	assert.Nil(t, mapping)
}

func TestMappingExists_UnknownMapping(t *testing.T) {
	assert.False(t, mappingExists(t.Context(), "xkey-test-mapping-that-does-not-exist"))
}
