//go:build codec_json

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

package handlers

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseLegacyEventTruncatedPush tests parseLegacyEvent with truncated data
func TestParseLegacyEventTruncatedPush(t *testing.T) {
	// Data too short for a legacy event (needs at least 28 bytes for header + minimal digest)
	data := []byte{
		// PCR index (4 bytes)
		0x00, 0x00, 0x00, 0x00,
		// Event type (4 bytes)
		0x01, 0x00, 0x00, 0x00,
		// Only partial data - missing digest and event data
	}

	reader := bytes.NewReader(data)
	_, err := parseLegacyEvent(reader)
	assert.Error(t, err)
}
