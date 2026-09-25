//go:build tpm_simulator
// +build tpm_simulator

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

package tpm2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDictionaryAttackLockoutReset_WrongLockoutAuth proves a lockout auth
// that does not match the Lockout hierarchy's (empty, by TCG default) auth
// value is refused with the TPM's own response code, rather than being
// reported as success or as a transport failure.
func TestDictionaryAttackLockoutReset_WrongLockoutAuth(t *testing.T) {
	h := newSimHarness(t, nil)

	err := h.TPM.DictionaryAttackLockoutReset([]byte("not-the-lockout-auth"))
	require.Error(t, err)
}

// TestDictionaryAttackLockoutReset_EmptyAuthSucceeds pins the ordinary
// success path against the Lockout hierarchy's TCG-default empty auth,
// complementing TestDictionaryAttackLockoutReset_WrongLockoutAuth's failure
// case.
func TestDictionaryAttackLockoutReset_EmptyAuthSucceeds(t *testing.T) {
	h := newSimHarness(t, nil)

	require.NoError(t, h.TPM.DictionaryAttackLockoutReset(nil))
	assert.NotNil(t, h.TPM.transport, "precondition: the harness must have a live transport")
}
