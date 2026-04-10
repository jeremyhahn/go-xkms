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

package gui

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFirmwareVersion_ValidSemver(t *testing.T) {
	result := ParseFirmwareVersion("1.2.3")
	assert.Equal(t, uint32(10203), result)
}

func TestParseFirmwareVersion_ZeroVersion(t *testing.T) {
	result := ParseFirmwareVersion("0.0.0")
	assert.Equal(t, uint32(0), result)
}

func TestParseFirmwareVersion_DevVersion(t *testing.T) {
	result := ParseFirmwareVersion("dev")
	assert.Equal(t, uint32(0), result)
}

func TestParseFirmwareVersion_PartialVersion(t *testing.T) {
	result := ParseFirmwareVersion("1.2")
	assert.Equal(t, uint32(0), result)
}
