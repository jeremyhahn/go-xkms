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

// TestAnswerCredentialChallenge_NilKey_Error proves AnswerCredentialChallenge
// refuses a nil ActivationKey with the typed ErrActivationKeyRequired,
// before it ever touches the TPM (a zero-value *TPM2, which would panic on
// any real TPM command, is enough to prove this).
func TestAnswerCredentialChallenge_NilKey_Error(t *testing.T) {
	tpm := &TPM2{}
	_, err := tpm.AnswerCredentialChallenge(nil, &CredentialChallenge{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrActivationKeyRequired)
}

// TestAnswerCredentialChallenge_NilChallenge_Error proves
// AnswerCredentialChallenge refuses a nil CredentialChallenge with the typed
// ErrCredentialChallengeRequired, before it ever touches the TPM.
func TestAnswerCredentialChallenge_NilChallenge_Error(t *testing.T) {
	tpm := &TPM2{}
	_, err := tpm.AnswerCredentialChallenge(&ActivationKey{}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCredentialChallengeRequired)
}
