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

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestOIDCCredentialClassOf pins the class every transport reports for the
// OIDC credential API's typed and sentinel errors, wrapped or not.
func TestOIDCCredentialClassOf(t *testing.T) {
	upstream := errors.New("provider unreachable")
	tests := []struct {
		name string
		err  error
		want Class
	}{
		{"config error", &credential.ConfigError{Detail: "issuer"}, ClassInvalidArgument},
		{"invalid segment", &scope.InvalidSegmentError{Field: "owner", Value: "a/b"}, ClassInvalidArgument},
		{"invalid scope", &scope.InvalidScopeError{Value: "::"}, ClassInvalidArgument},
		{"retryable refresh", &credential.RefreshError{Name: "c", Err: upstream}, ClassUnavailable},
		// A refresh the provider rejected for good is the credential's state:
		// the Relogin error falls through to its ErrReloginRequired sentinel.
		{"relogin refresh", &credential.RefreshError{Name: "c", Relogin: true, Err: upstream}, ClassFailedPrecondition},
		{"wrapped config error", fmt.Errorf("create: %w", &credential.ConfigError{Detail: "x"}), ClassInvalidArgument},
		{"not configured", xkms.ErrNotConfigured, ClassUnavailable},
		{"not found", credential.ErrNotFound, ClassNotFound},
		{"exists", credential.ErrExists, ClassAlreadyExists},
		{"scope refused", scope.ErrRefused, ClassPermissionDenied},
		{"corrupt record", credential.ErrCorruptRecord, ClassDataLoss},
		{"device code expired", oidc.ErrDeviceCodeExpired, ClassFailedPrecondition},
		{"wrapped sentinel", fmt.Errorf("get: %w", credential.ErrNotFound), ClassNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := OIDCCredentialClassOf(tt.err)
			assert.True(t, ok, "%T must classify", tt.err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestOIDCCredentialClassOf_Unclassified pins that nil and foreign errors are
// not classified, so transports fall back to an internal error.
func TestOIDCCredentialClassOf_Unclassified(t *testing.T) {
	for _, err := range []error{nil, errors.New("foreign")} {
		got, ok := OIDCCredentialClassOf(err)
		assert.False(t, ok, "%v", err)
		assert.Equal(t, ClassInternal, got)
	}
}
