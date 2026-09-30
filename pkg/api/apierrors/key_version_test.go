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

	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestKeyVersionClassOf proves every key-version error classifies the way
// the API promises -- a ciphertext needing a version is a bad request, a
// missing version is not found, a current-version refusal is a precondition
// -- including when wrapped in a role lookup.
func TestKeyVersionClassOf(t *testing.T) {
	tests := []struct {
		err  error
		want Class
	}{
		{&keyversion.KeyVersionRequiredError{KeyID: "k", Enabled: []uint32{2, 1}}, ClassInvalidArgument},
		{&keyversion.ReservedKeyIDError{KeyID: "k--v2"}, ClassInvalidArgument},
		{&keyversion.InvalidVersionError{}, ClassInvalidArgument},
		{&keyversion.InvalidRecordKeyError{Field: "backend", Value: "a/b"}, ClassInvalidArgument},
		{&keyversion.VersionNotFoundError{KeyID: "k", Version: 9}, ClassNotFound},
		{&xkms.KeyVersionMissingError{KeyID: "k", Version: 2}, ClassNotFound},
		{&keyversion.CurrentVersionError{KeyID: "k", Version: 2, Operation: "disable"}, ClassFailedPrecondition},
		{&keyversion.RetiredVersionError{KeyID: "k", Version: 1}, ClassFailedPrecondition},
		{&keyversion.VersionUnavailableError{KeyID: "k", Version: 1, State: keyversion.StateDisabled}, ClassFailedPrecondition},
		{&xkms.KeyExistsError{KeyID: "k"}, ClassAlreadyExists},
		{&xkms.KeyRotationUnsupportedError{KeyID: "k", Reason: "x25519"}, ClassUnimplemented},
		{xkms.ErrKeyVersionsNotConfigured, ClassUnavailable},
		{&xkms.ErrRoleLookup{Role: "key", Name: "k", Err: &keyversion.CurrentVersionError{KeyID: "k"}}, ClassFailedPrecondition},
		{fmt.Errorf("wrapped: %w", &keyversion.KeyVersionRequiredError{KeyID: "k"}), ClassInvalidArgument},
	}
	for _, tt := range tests {
		got, ok := KeyVersionClassOf(tt.err)
		assert.True(t, ok, "%T must classify", tt.err)
		assert.Equal(t, tt.want, got, "%v", tt.err)
	}
}

// TestKeyVersionClassOf_Unclassified proves an error outside the model, and
// nil, are not classified -- and that ErrNotConfigured alone is not the
// key-version sentinel.
func TestKeyVersionClassOf_Unclassified(t *testing.T) {
	for _, err := range []error{nil, errors.New("disk full"), xkms.ErrKeyNotFound, xkms.ErrNotConfigured} {
		_, ok := KeyVersionClassOf(err)
		assert.False(t, ok, "%v", err)
	}
}
