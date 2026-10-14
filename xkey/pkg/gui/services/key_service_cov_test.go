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

package services

import (
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
)

// TestKeyService_LocalTPMKeyPolicyBookkeeping covers recording and forgetting
// the policy assignment of a key on xKey's own TPM before a policy store is
// bound: a well-formed key ID is accepted as a no-op, a missing one is
// rejected.
func TestKeyService_LocalTPMKeyPolicyBookkeeping(t *testing.T) {
	svc := NewKeyService()
	svc.SetTPMPolicyService(NewTPMPolicyService())
	tpm := string(xkms.BackendTypeTPM2)

	assert.NoError(t, svc.recordLocalTPMKey("local", tpm, "tpm2:signing:ecdsa-p256:mykey", "default"))
	assert.NoError(t, svc.forgetLocalTPMKey("local", tpm, "tpm2:signing:ecdsa-p256:mykey"))

	assert.ErrorIs(t, svc.recordLocalTPMKey("local", tpm, "", "default"), ErrTPMPolicyKeyIDRequired)
	assert.ErrorIs(t, svc.forgetLocalTPMKey("local", tpm, ""), ErrTPMPolicyKeyIDRequired)

	// Server-side keys are the server's to record, even with a bad ID.
	assert.NoError(t, svc.recordLocalTPMKey("server", tpm, "", "default"))
	assert.NoError(t, svc.forgetLocalTPMKey("server", tpm, ""))
}
