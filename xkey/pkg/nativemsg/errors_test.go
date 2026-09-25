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

package nativemsg

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDetailError_Error verifies the wrapped error message is followed
// directly by the detail text, with no separator inserted, and that
// errors.Is still matches the wrapped sentinel through Unwrap.
func TestDetailError_Error(t *testing.T) {
	err := &DetailError{Err: ErrHandshakeRequired, Detail: ": no session established"}

	assert.Equal(t, "nativemsg: handshake not completed: no session established", err.Error())
	assert.True(t, errors.Is(err, ErrHandshakeRequired))
}
