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

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestMapKeyOpError_NotFoundSentinels pins go-xkms#814: xkms.ErrKeyNotFound
// and xkms.ErrBackendNotFound -- whether returned bare or wrapped (the shape
// pkg/xkms/service.go's LookupBackend and servicer_helpers.go's
// findKeyAttrs actually return them in) -- classify onto
// sdkssh.JSONRPCCodeNotFound, the code pkg/apimodule's keyOpCodeToWire
// already renders as wire.CodeNotFound. Before this fix both sentinels
// mapped to ErrCodeInternalError, so a missing key or backend was
// indistinguishable from a genuine server fault (see keyOpSentinelCodes'
// doc comment history).
func TestMapKeyOpError_NotFoundSentinels(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"bare ErrKeyNotFound", xkms.ErrKeyNotFound},
		{"wrapped ErrKeyNotFound", &errs.Wrapped{Msg: "key not found: k1", Err: xkms.ErrKeyNotFound}},
		{"bare ErrBackendNotFound", xkms.ErrBackendNotFound},
		{"wrapped ErrBackendNotFound", &xkms.ErrBackendLookup{Sentinel: xkms.ErrBackendNotFound, Name: "b1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapKeyOpError(tt.err)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, sdkssh.JSONRPCCodeNotFound, keyErr.Code)
		})
	}
}

// TestMapKeyOpError_RoleLookupIsNotFound pins go-xkms#912: *xkms.ErrRoleLookup
// classifies onto sdkssh.JSONRPCCodeNotFound, matching
// pkg/api/grpc/errors_keyops.go's mapKeyOpError (codes.NotFound) and
// go-qrdb's own MCP wire contract, which classifies its own
// *role.RoleNotFoundError identically to its gRPC transport. Before this fix
// MCP alone reported Invalid params for this condition, diverging from both.
func TestMapKeyOpError_RoleLookupIsNotFound(t *testing.T) {
	err := mapKeyOpError(&xkms.ErrRoleLookup{Role: "target key backend", Name: "hsm", Err: xkms.ErrBackendNotFound})

	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, keyErr.Code)
}

// TestMapKeyOpError_UnclassifiedErrorIsInternal proves mapKeyOpError's
// floor: an error matching none of keyOpSentinelCodes, *xkms.ErrRoleLookup,
// or *xkms.ErrValidation still becomes a classified *KeyOpError rather than
// reaching the caller unclassified, and reports ErrCodeInternalError -- the
// same fallback mapKeyOpError used before go-xkms#814, unchanged for a
// condition that is not a not-found case.
func TestMapKeyOpError_UnclassifiedErrorIsInternal(t *testing.T) {
	err := mapKeyOpError(errors.New("backend exploded"))

	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeInternalError, keyErr.Code)
}

// TestMapKeyOpError_Nil proves mapKeyOpError passes a nil error through
// unchanged, so every handler's "if err != nil { return nil,
// mapKeyOpError(err) }" call site stays correct without its own nil guard.
func TestMapKeyOpError_Nil(t *testing.T) {
	assert.NoError(t, mapKeyOpError(nil))
}
