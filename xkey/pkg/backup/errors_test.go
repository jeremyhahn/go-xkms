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

package backup

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDetailError_Error verifies the wrapped error message is followed
// directly by the detail text, with no separator inserted (callers supply
// their own leading punctuation in Detail), and that errors.Is still
// matches the wrapped sentinel.
func TestDetailError_Error(t *testing.T) {
	err := &DetailError{Err: ErrRestoreFailed, Detail: ": nil archive"}

	assert.Equal(t, "backup: restore failed: nil archive", err.Error())
	assert.True(t, errors.Is(err, ErrRestoreFailed))
}

// TestSentinelCauseError_Error verifies the message joins the sentinel and
// the cause, and that errors.Is matches both through Unwrap.
func TestSentinelCauseError_Error(t *testing.T) {
	cause := errors.New("aead: invalid key size")
	err := &SentinelCauseError{Sentinel: ErrEncryptionFailed, Cause: cause}

	assert.Equal(t, "backup: encryption failed: aead: invalid key size", err.Error())
	assert.True(t, errors.Is(err, ErrEncryptionFailed))
	assert.True(t, errors.Is(err, cause))
}
