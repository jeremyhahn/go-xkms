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

// TestParseSpecIDEventTruncatedAlgorithmsPush tests parseSpecIDEvent with truncated algorithm data
func TestParseSpecIDEventTruncatedAlgorithmsPush(t *testing.T) {
	// Valid signature but truncated before algorithm data
	data := []byte{
		// Signature: "Spec ID Event03" + null
		'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ',
		'E', 'v', 'e', 'n', 't', '0', '3', 0,
		// platformClass (4 bytes)
		0x00, 0x00, 0x00, 0x00,
		// specVersionMinor (1 byte)
		0x00,
		// specVersionMajor (1 byte)
		0x02,
		// specErrata (1 byte)
		0x00,
		// uintnSize (1 byte)
		0x04,
		// numberOfAlgorithms (4 bytes) - indicates 2 algorithms
		0x02, 0x00, 0x00, 0x00,
		// Only one algorithm provided (truncated)
		0x04, 0x00, 0x14, 0x00,
		// Missing second algorithm - truncated
	}

	_, err := parseSpecIDEvent(data)
	assert.Error(t, err)
}

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

// TestSpecIDAlgorithmStruct tests SpecIDAlgorithm struct creation
func TestSpecIDAlgorithmStruct(t *testing.T) {
	alg := SpecIDAlgorithm{
		AlgorithmID: 0x000B,
		DigestSize:  32,
	}

	assert.Equal(t, uint16(0x000B), alg.AlgorithmID)
	assert.Equal(t, uint16(32), alg.DigestSize)
}
