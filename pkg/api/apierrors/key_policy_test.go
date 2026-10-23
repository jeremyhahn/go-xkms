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

package apierrors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestKeyPolicyClassOf proves every key management error classifies the way
// the API promises, including when wrapped: a missing store is unavailable,
// a policy refusal is permission denied, an exhausted AEAD key is a resource
// limit.
func TestKeyPolicyClassOf(t *testing.T) {
	tests := []struct {
		err  error
		want Class
	}{
		{xkms.ErrKeyPoliciesNotConfigured, ClassUnavailable},
		{&xkms.InvalidKeyPolicyError{Field: "status", Reason: "unknown"}, ClassInvalidArgument},
		{&xkms.KeyKindError{KeyID: "k", Operation: "public key"}, ClassInvalidArgument},
		{&keypolicy.InvalidRecordKeyError{}, ClassInvalidArgument},
		{&xkms.UnenforceablePolicyError{KeyID: "k", Field: "require_mfa"}, ClassUnimplemented},
		{&xkms.BackendTestUnsupportedError{}, ClassUnimplemented},
		{&xkms.KeyStatusTransitionError{KeyID: "k", From: "compromised", To: "enabled"}, ClassFailedPrecondition},
		{&keypolicy.KeyUnavailableError{KeyID: "k"}, ClassFailedPrecondition},
		{&keypolicy.PolicyDeniedError{KeyID: "k", Operation: keypolicy.OpSign}, ClassPermissionDenied},
		{&keypolicy.SafetyLimitError{KeyID: "k", Limit: "operations"}, ClassResourceExhausted},
		{fmt.Errorf("wrapped: %w", &keypolicy.PolicyDeniedError{KeyID: "k"}), ClassPermissionDenied},
	}
	for _, tt := range tests {
		got, ok := KeyPolicyClassOf(tt.err)
		assert.True(t, ok, "%T must classify", tt.err)
		assert.Equal(t, tt.want, got, "%v", tt.err)
	}
}

// TestKeyPolicyClassOf_Unclassified proves errors outside the key management
// API, and the bare not-configured sentinel, fall through to the other
// tables.
func TestKeyPolicyClassOf_Unclassified(t *testing.T) {
	for _, err := range []error{nil, errors.New("disk full"), xkms.ErrKeyNotFound, xkms.ErrNotConfigured} {
		_, ok := KeyPolicyClassOf(err)
		assert.False(t, ok, "%v", err)
	}
}
