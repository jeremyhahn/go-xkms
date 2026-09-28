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

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestErrPeerCredentialsUnsupported_Error pins the message an operator sees
// when a deployment on an unsupported platform attempts to construct a Unix
// Admin API listener: it must name the offending GOOS.
func TestErrPeerCredentialsUnsupported_Error(t *testing.T) {
	err := ErrPeerCredentialsUnsupported{GOOS: "windows"}
	assert.Equal(t, "peer credential extraction is not implemented for GOOS=windows", err.Error())
}

// TestErrClientHandshakeUnsupported_Error pins the message returned when
// something attempts to dial the Unix peer-credential transport as a
// gRPC client, which xkmsd never does.
func TestErrClientHandshakeUnsupported_Error(t *testing.T) {
	err := ErrClientHandshakeUnsupported{}
	assert.Equal(t, "peer credential transport does not support client-side handshakes", err.Error())
}

// TestErrInvalidUserID_Error pins the message named for a wire-format user
// id that failed to parse as a uint64, including the offending value.
func TestErrInvalidUserID_Error(t *testing.T) {
	err := ErrInvalidUserID{Value: "not-a-number"}
	assert.Equal(t, `invalid user id: "not-a-number" is not a uint64`, err.Error())
}

// TestParseUserID_EmptyStringYieldsZero pins the qrdb convention: an empty
// wire-format id means "unset" and parses to 0, not an error.
func TestParseUserID_EmptyStringYieldsZero(t *testing.T) {
	id, err := parseUserID("")
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), id)
}

// TestParseUserID_ValidDecimal verifies a well-formed decimal wire-format id
// parses to the matching uint64.
func TestParseUserID_ValidDecimal(t *testing.T) {
	id, err := parseUserID("42")
	assert.NoError(t, err)
	assert.Equal(t, uint64(42), id)
}

// TestParseUserID_InvalidValue verifies a non-decimal wire-format id is
// refused with the typed ErrInvalidUserID naming the offending value, rather
// than a bare strconv error.
func TestParseUserID_InvalidValue(t *testing.T) {
	_, err := parseUserID("not-a-number")
	invalid, ok := err.(ErrInvalidUserID)
	if !ok {
		t.Fatalf("expected ErrInvalidUserID, got %T: %v", err, err)
	}
	assert.Equal(t, "not-a-number", invalid.Value)
}

// TestFormatUserID verifies the inverse of parseUserID renders qrdb's uint64
// id as the decimal wire-format string.
func TestFormatUserID(t *testing.T) {
	assert.Equal(t, "42", formatUserID(42))
	assert.Equal(t, "0", formatUserID(0))
}
