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

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/image"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestSigningKeyClassOf proves every signing-key error classifies the way
// the API promises -- a malformed repository or key is a bad request, an
// unbound repository is not found, a binding change without the permission
// is denied -- including the appraisal's typed errors.
func TestSigningKeyClassOf(t *testing.T) {
	tests := []struct {
		err  error
		want Class
	}{
		{xkms.ErrNotConfigured, ClassUnavailable},
		{&xkms.SigningKeyPermissionError{Permission: "attestation_signing_keys:bind", Err: errors.New("denied")}, ClassPermissionDenied},
		{appraisal.ErrNilRequest, ClassInvalidArgument},
		{&appraisal.RepositoryError{Repository: "Acme/App"}, ClassInvalidArgument},
		{&appraisal.SigningKeyError{KeyID: "a/b", Cause: errors.New("bad key id")}, ClassInvalidArgument},
		{appraisal.ErrInvalidTenant, ClassInvalidArgument},
		{fmt.Errorf("get: %w", appraisal.ErrRecordNotFound), ClassNotFound},
		{appraisal.ErrStoreUnavailable, ClassUnavailable},
		{&xkms.CoRIMSignError{Repository: "acme/app", KeyID: "release-signing", Err: refvalue.ErrMalformed}, ClassInvalidArgument},
		{&xkms.CoRIMSignError{Repository: "acme/app", KeyID: "release-signing", Err: refvalue.ErrMeta}, ClassInvalidArgument},
		{&xkms.CoRIMSignError{Repository: "acme/app", KeyID: "release-signing", Err: refvalue.ErrSignerKey}, ClassFailedPrecondition},
		{xkms.ErrKeyNotFound, ClassFailedPrecondition},
		{xkms.ErrSystemTenantImageSigning, ClassFailedPrecondition},
		{&xkms.ImageSignError{Reference: "registry.example/acme/app:1", KeyID: "release-signing", Err: image.ErrRegistryCredentials}, ClassInvalidArgument},
		{&xkms.ImageSignError{Reference: "registry.example/acme/app:1", KeyID: "release-signing", Err: image.ErrManifestNotFound}, ClassNotFound},
		{&xkms.ImageSignError{Reference: "registry.example/acme/app:1", KeyID: "release-signing", Err: image.ErrRegistryUnavailable}, ClassUnavailable},
		{&xkms.ImageSignError{Reference: "registry.example/acme/app:1", KeyID: "release-signing", Err: image.ErrRegistryAuth}, ClassFailedPrecondition},
		{image.ErrInvalidReference, ClassInvalidArgument},
		// admitKey's refusals keep the class KeyPolicyClassOf gives them.
		{&keypolicy.PolicyDeniedError{KeyID: "release-signing", Operation: keypolicy.OpSign, Reason: "caller not allowed"}, ClassPermissionDenied},
		{&keypolicy.KeyUnavailableError{KeyID: "release-signing", Status: keypolicy.StatusDisabled}, ClassFailedPrecondition},
		{&keypolicy.KeyUnavailableError{KeyID: "release-signing", Status: keypolicy.StatusRevoked}, ClassFailedPrecondition},
	}
	for _, tt := range tests {
		got, ok := SigningKeyClassOf(tt.err)
		assert.True(t, ok, "%T must classify", tt.err)
		assert.Equal(t, tt.want, got, "%v", tt.err)
	}
}

// TestSigningKeyClassOf_Unclassified proves an error outside the model, and
// nil, are not classified.
func TestSigningKeyClassOf_Unclassified(t *testing.T) {
	signFailed := &xkms.CoRIMSignError{Repository: "acme/app", KeyID: "release-signing", Err: refvalue.ErrSign}
	for _, err := range []error{nil, errors.New("disk full"), signFailed} {
		_, ok := SigningKeyClassOf(err)
		assert.False(t, ok, "%v", err)
	}
}
