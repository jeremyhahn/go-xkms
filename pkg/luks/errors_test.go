// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package luks

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSealParentInvalidError_Message pins that the message names the bad
// input in whichever form it arrived: the raw config string, or the
// out-of-range constant.
func TestSealParentInvalidError_Message(t *testing.T) {
	raw := &SealParentInvalidError{Raw: "srk"}
	assert.Equal(t, ErrInvalidSealParent.Error()+`: "srk" (must be "psrk" or "ssrk")`, raw.Error())
	assert.ErrorIs(t, raw, ErrInvalidSealParent)

	value := &SealParentInvalidError{Value: 7}
	assert.Equal(t, ErrInvalidSealParent.Error()+": value 7 (must be SealParentPSRK or SealParentSSRK)", value.Error())
	assert.ErrorIs(t, value, ErrInvalidSealParent)
}

// TestExecutorError_Message pins that the operation and, when known, the path
// appear in the message, and that the cause stays reachable.
func TestExecutorError_Message(t *testing.T) {
	cause := errors.New("device busy")

	withPath := &ExecutorError{Operation: "luks_lock", Path: "xkms-test", Err: cause}
	assert.Equal(t, "luks: luks_lock failed for xkms-test: device busy", withPath.Error())
	assert.ErrorIs(t, withPath, cause)

	noPath := &ExecutorError{Operation: "protect_passphrase", Err: cause}
	assert.Equal(t, "luks: protect_passphrase failed: device busy", noPath.Error())
	assert.ErrorIs(t, noPath, cause)
}
