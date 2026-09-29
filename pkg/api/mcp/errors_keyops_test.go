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

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
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

// TestMapKeyOpError_AEADNonceSentinels pins go-xkms#1223: a reused AEAD
// nonce and a full nonce tracker reach mapKeyOpError wrapped exactly as
// pkg/xkms's claimAEADNonce / claimGeneratedAEADNonce actually wrap them
// (*xkms.ErrKeyOperation), from both the generic Encrypt RPC and
// WrapKeyByID's AES-GCM wrap path, and must render as the JSON-RPC duplicate
// code and the internal-error floor respectively (JSON-RPC has no dedicated
// ResourceExhausted member), with Classified set so the resource-exhausted
// case's text is not withheld the way a genuinely unclassified fault's is.
func TestMapKeyOpError_AEADNonceSentinels(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nonce reuse via Encrypt", &xkms.ErrKeyOperation{Operation: "aead encrypt", KeyID: "k1", Err: aead.ErrNonceReuse}, sdkssh.JSONRPCCodeDuplicate},
		{"nonce reuse via WrapKeyByID", &xkms.ErrKeyOperation{Operation: "aes-gcm wrap", KeyID: "k1", Err: aead.ErrNonceReuse}, sdkssh.JSONRPCCodeDuplicate},
		{"nonce tracker full via Encrypt", &xkms.ErrKeyOperation{Operation: "aead encrypt", KeyID: "k1", Err: aead.ErrNonceTrackerFull}, ErrCodeInternalError},
		{"nonce tracker full via WrapKeyByID", &xkms.ErrKeyOperation{Operation: "aes-gcm wrap", KeyID: "k1", Err: aead.ErrNonceTrackerFull}, ErrCodeInternalError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapKeyOpError(tt.err)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, tt.want, keyErr.Code)
			assert.False(t, keyErr.Internal(),
				"an AEAD nonce-safety refusal must not be reported with the withheld internal-fault text")
		})
	}
}

// TestMapKeyOpError_CallerNonceNotSupported pins go-xkms#1223: a symmetric
// backend that refuses a caller-supplied nonce (AWS KMS, GCP KMS, Vault
// Transit, the paired phone) reports Invalid params, matching the 400 REST
// and InvalidArgument gRPC report for the same sentinel.
func TestMapKeyOpError_CallerNonceNotSupported(t *testing.T) {
	err := mapKeyOpError(backend.ErrCallerNonceNotSupported)
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeInvalidParams, keyErr.Code)
}
