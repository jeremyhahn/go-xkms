// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package tpmdev_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/sdk/go/tpmdev"
)

// A test binary that has not opted in never reaches the host's hardware TPM,
// and a path that is not a device fails either way; both are errors.
func TestOpenRefusesAMissingDevice(t *testing.T) {
	_, err := tpmdev.Open(filepath.Join(t.TempDir(), "tpm0"))
	assert.Error(t, err)
}

func TestOpenRefusesTheHardwareTPM(t *testing.T) {
	_, err := tpmdev.Open("/dev/tpmrm0")
	assert.Error(t, err)
}
