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

package grpc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestMapPasswordError_VaultSentinels pins the status codes of the errors the
// personal-vault RPCs and PasswordStoreUnlock return. Each is matched through
// a wrapping error, as the service layer may wrap them.
func TestMapPasswordError_VaultSentinels(t *testing.T) {
	cases := []struct {
		err  error
		want codes.Code
	}{
		{staticpw.ErrVaultInvalidCredential, codes.InvalidArgument},
		{staticpw.ErrVaultRecoveryFactor, codes.InvalidArgument},
		{staticpw.ErrVaultNotInitialized, codes.FailedPrecondition},
		{staticpw.ErrVaultCredentialRejected, codes.Unauthenticated},
		{staticpw.ErrVaultFactorNotFound, codes.NotFound},
		{staticpw.ErrVaultLastFactor, codes.FailedPrecondition},
		{staticpw.ErrVaultPasskeyExists, codes.AlreadyExists},
		{staticpw.ErrStoreLocked, codes.FailedPrecondition},
		{staticpw.ErrStoreNotLocked, codes.FailedPrecondition},
		{seal.ErrTenantSealed, codes.Unavailable},
		{xkms.ErrOperationNotSupported, codes.Unimplemented},
		{xkms.ErrNotConfigured, codes.Unavailable},
		{xkms.ErrNilRequest, codes.InvalidArgument},
	}

	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			got := mapPasswordError(errors.Join(errors.New("context"), tc.err))
			require.Error(t, got)
			assert.Equal(t, tc.want, status.Code(got))
		})
	}
}

// TestMapPasswordError_RejectedCredentialSaysNothingMore proves a rejected
// credential reports only the fixed sentinel text: which factor was tried
// and why it failed must not reach the caller.
func TestMapPasswordError_RejectedCredentialSaysNothingMore(t *testing.T) {
	got := mapPasswordError(errors.Join(staticpw.ErrVaultCredentialRejected, errors.New("factor f-123 tag mismatch")))

	assert.Equal(t, codes.Unauthenticated, status.Code(got))
	assert.NotContains(t, got.Error(), "f-123")
	assert.NotContains(t, got.Error(), "tag mismatch")
}

// TestMapPasswordError_NilAndUnknown covers the edges: nil maps to nil and an
// unrecognised error is Internal.
func TestMapPasswordError_NilAndUnknown(t *testing.T) {
	assert.NoError(t, mapPasswordError(nil))
	assert.Equal(t, codes.Internal, status.Code(mapPasswordError(errors.New("boom"))))
}
