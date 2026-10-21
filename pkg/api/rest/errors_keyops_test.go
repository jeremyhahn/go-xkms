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

package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestMapKeyOpError_AEADNonceSentinels pins go-xkms#1223: a reused AEAD
// nonce and a full nonce tracker reach mapKeyOpError classified via
// apierrors.AEADSentinelClasses regardless of which wrapper carries the
// sentinel -- ClassOf uses errors.Is, so it sees through both
// *xkms.ErrKeyOperation, the shape WrapKeyByID's AES-GCM wrap still
// produces, and *xkms.ErrOperationWrap, the shape the generic Encrypt RPC
// produces since go-xkms#1201 moved the claim into the backend's own
// Encrypt (pkg/backend's ClaimAEADNonce/ClaimGeneratedAEADNonce). Both must
// report 409 Conflict and 503 Service Unavailable respectively rather than
// falling through to the 500 catch-all a caller cannot distinguish from a
// genuine server fault.
func TestMapKeyOpError_AEADNonceSentinels(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nonce reuse via Encrypt", &xkms.ErrKeyOperation{Operation: "aead encrypt", KeyID: "k1", Err: aead.ErrNonceReuse}, http.StatusConflict},
		{"nonce reuse via WrapKeyByID", &xkms.ErrKeyOperation{Operation: "aes-gcm wrap", KeyID: "k1", Err: aead.ErrNonceReuse}, http.StatusConflict},
		{"nonce tracker full via Encrypt", &xkms.ErrKeyOperation{Operation: "aead encrypt", KeyID: "k1", Err: aead.ErrNonceTrackerFull}, http.StatusServiceUnavailable},
		{"nonce tracker full via WrapKeyByID", &xkms.ErrKeyOperation{Operation: "aes-gcm wrap", KeyID: "k1", Err: aead.ErrNonceTrackerFull}, http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mapKeyOpError(w, tt.err)
			if w.Code != tt.want {
				t.Errorf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

// TestMapKeyOpError_CallerNonceNotSupported pins go-xkms#1223: a symmetric
// backend that refuses a caller-supplied nonce (AWS KMS, GCP KMS, Vault
// Transit, the paired phone) reports 400 Bad Request, matching gRPC's
// InvalidArgument and MCP's Invalid params for the same sentinel.
func TestMapKeyOpError_CallerNonceNotSupported(t *testing.T) {
	w := httptest.NewRecorder()
	mapKeyOpError(w, backend.ErrCallerNonceNotSupported)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestMapKeyOpError_WrapTargetNotSymmetric proves a WrapKeyByID refusal of a
// non-symmetric target maps to 400, beside an asymmetric export refusal
// (go-xkms#1634).
func TestMapKeyOpError_WrapTargetNotSymmetric(t *testing.T) {
	for name, err := range map[string]error{
		"typed":   &xkms.ErrWrapTarget{KeyID: "ecdsa-key", Err: xkms.ErrWrapTargetNotSymmetric},
		"backend": backend.ErrAsymmetricKeyExportNotAllowed,
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mapKeyOpError(w, err)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}
