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
)

// TestDictionaryAttackLockoutReset_NoTransport proves the method refuses to
// build and send a TPM2_DictionaryAttackLockReset command against a TPM2
// that was never opened, rather than dereferencing a nil transport.
func TestDictionaryAttackLockoutReset_NoTransport(t *testing.T) {
	tpm := &TPM2{}
	err := tpm.DictionaryAttackLockoutReset([]byte("lockout-auth"))
	assert.ErrorIs(t, err, ErrTransportNotInitialized)
}
