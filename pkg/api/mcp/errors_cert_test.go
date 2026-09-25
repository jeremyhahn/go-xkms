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

package mcp

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestCertOperationError classifies a certificate-storage failure as
// internal, mirroring pkg/api/grpc/service.go's unconditional codes.Internal
// for SaveCert/DeleteCert/ListCerts/CertExists/SaveCertChain/GetCertChain.
func TestCertOperationError(t *testing.T) {
	cause := errors.New("disk full")
	err := certOperationError("failed to save certificate", cause)

	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeInternalError, keyErr.Code)
	assert.ErrorIs(t, err, cause)
}

// TestGetCertError classifies any GetCert failure as Not found, mirroring
// pkg/api/grpc/service.go's GetCert, which reports codes.NotFound
// unconditionally.
func TestGetCertError(t *testing.T) {
	cause := errors.New("storage: not found")
	err := getCertError("failed to get certificate", cause)

	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, keyErr.Code)
	assert.ErrorIs(t, err, cause)
}

// TestMapCAError_DomainSentinels asserts the JSON-RPC code for each sentinel
// mapCAError classifies, matching pkg/api/grpc/service_ca.go's classification
// of the same conditions (a nil CA instance -> Unavailable; a missing
// required field -> InvalidArgument).
func TestMapCAError_DomainSentinels(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code int
	}{
		{"CA not configured", xkms.ErrNotConfigured, ErrCodeServiceUnavailable},
		{"nil request", xkms.ErrNilRequest, ErrCodeInvalidParams},
		{"nil data", xkms.ErrNilData, ErrCodeInvalidParams},
		{"validation failure", &xkms.ErrValidation{Sentinel: xkms.ErrMissingRequiredField, Detail: "common_name is required"}, ErrCodeInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapCAError(tt.err)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, tt.code, keyErr.Code)
			assert.ErrorIs(t, err, tt.err)
		})
	}
}

// TestMapCAError_Unclassified proves mapCAError's floor: a wrapped
// *xkms.ErrCAOperation (or any other error outside its sentinel checks)
// becomes ErrCodeInternalError, matching gRPC's fixed codes.Internal
// fallback for a CA servicer failure.
func TestMapCAError_Unclassified(t *testing.T) {
	err := mapCAError(&xkms.ErrCAOperation{Operation: "sign csr", Err: errors.New("hsm exploded")})
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeInternalError, keyErr.Code)
}

// TestMapCAError_Nil proves mapCAError passes a nil error through unchanged.
func TestMapCAError_Nil(t *testing.T) {
	assert.NoError(t, mapCAError(nil))
}
