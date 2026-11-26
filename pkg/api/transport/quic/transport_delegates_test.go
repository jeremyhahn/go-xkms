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

package quic

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// delegateCall is one Transport method delegating to a wire client, and
// the method and path it must send; an empty path is not pinned here.
type delegateCall struct {
	name         string
	call         func(context.Context, *Transport) error
	method, path string
}

func delegateCalls() []delegateCall {
	key := &transport.KeyManagementRequest{KeyID: "k"}
	backend := &transport.BackendRequest{Backend: "software"}
	root := &transport.TrustRootRequest{Fingerprint: "ab12"}
	post := http.MethodPost
	return []delegateCall{
		{"Rewrap", func(ctx context.Context, tr *Transport) error {
			_, err := tr.Rewrap(ctx, &transport.RewrapRequest{})
			return err
		}, post, "/api/v1/keys/rewrap"},
		{"EncryptBatch", func(ctx context.Context, tr *Transport) error {
			_, err := tr.EncryptBatch(ctx, &transport.EncryptBatchRequest{KeyID: "k"})
			return err
		}, post, "/api/v1/keys/k/encrypt-batch"},
		{"DecryptBatch", func(ctx context.Context, tr *Transport) error {
			_, err := tr.DecryptBatch(ctx, &transport.DecryptBatchRequest{KeyID: "k"})
			return err
		}, post, "/api/v1/keys/k/decrypt-batch"},
		{"GenerateDataKey", func(ctx context.Context, tr *Transport) error {
			_, err := tr.GenerateDataKey(ctx, &transport.GenerateDataKeyRequest{KeyID: "k"})
			return err
		}, post, "/api/v1/keys/k/data-key"},
		{"GenerateWrappedDataKey", func(ctx context.Context, tr *Transport) error {
			_, err := tr.GenerateWrappedDataKey(ctx, &transport.GenerateDataKeyRequest{KeyID: "k"})
			return err
		}, post, "/api/v1/keys/k/wrapped-data-key"},
		{"GenerateHMAC", func(ctx context.Context, tr *Transport) error {
			_, err := tr.GenerateHMAC(ctx, &transport.GenerateHMACRequest{KeyID: "k"})
			return err
		}, post, "/api/v1/keys/k/hmac"},
		{"VerifyHMAC", func(ctx context.Context, tr *Transport) error {
			_, err := tr.VerifyHMAC(ctx, &transport.VerifyHMACRequest{KeyID: "k"})
			return err
		}, post, "/api/v1/keys/k/hmac/verify"},
		{"GenerateRandom", func(ctx context.Context, tr *Transport) error {
			_, err := tr.GenerateRandom(ctx, &transport.GenerateRandomRequest{Length: 8})
			return err
		}, post, "/api/v1/random"},
		{"Hash", func(ctx context.Context, tr *Transport) error {
			_, err := tr.Hash(ctx, &transport.HashRequest{})
			return err
		}, post, "/api/v1/hash"},

		{"GetPublicKey", func(ctx context.Context, tr *Transport) error {
			_, err := tr.GetPublicKey(ctx, &transport.GetPublicKeyRequest{KeyID: "k"})
			return err
		}, "", ""},
		{"RevokeKey", func(ctx context.Context, tr *Transport) error {
			_, err := tr.RevokeKey(ctx, &transport.RevokeKeyRequest{KeyID: "k"})
			return err
		}, "", ""},
		{"UpdateKeyStatus", func(ctx context.Context, tr *Transport) error {
			_, err := tr.UpdateKeyStatus(ctx, &transport.UpdateKeyStatusRequest{KeyID: "k"})
			return err
		}, "", ""},
		{"GetKeyMetadata", func(ctx context.Context, tr *Transport) error {
			_, err := tr.GetKeyMetadata(ctx, key)
			return err
		}, "", ""},
		{"UpdateKeyMetadata", func(ctx context.Context, tr *Transport) error {
			_, err := tr.UpdateKeyMetadata(ctx, &transport.UpdateKeyMetadataRequest{KeyID: "k"})
			return err
		}, "", ""},
		{"SetKeyPolicy", func(ctx context.Context, tr *Transport) error {
			_, err := tr.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{KeyID: "k", Policy: &transport.KeyPolicy{}})
			return err
		}, "", ""},
		{"GetKeyPolicy", func(ctx context.Context, tr *Transport) error {
			_, err := tr.GetKeyPolicy(ctx, key)
			return err
		}, "", ""},
		{"DeleteKeyPolicy", func(ctx context.Context, tr *Transport) error {
			_, err := tr.DeleteKeyPolicy(ctx, key)
			return err
		}, "", ""},
		{"SetKeyRotationPolicy", func(ctx context.Context, tr *Transport) error {
			_, err := tr.SetKeyRotationPolicy(ctx, &transport.SetKeyRotationPolicyRequest{KeyID: "k", Policy: &transport.RotationPolicy{}})
			return err
		}, "", ""},
		{"GetKeyRotationPolicy", func(ctx context.Context, tr *Transport) error {
			_, err := tr.GetKeyRotationPolicy(ctx, key)
			return err
		}, "", ""},
		{"DeleteKeyRotationPolicy", func(ctx context.Context, tr *Transport) error {
			_, err := tr.DeleteKeyRotationPolicy(ctx, key)
			return err
		}, "", ""},
		{"GetSupportedAlgorithms", func(ctx context.Context, tr *Transport) error {
			_, err := tr.GetSupportedAlgorithms(ctx, backend)
			return err
		}, "", ""},
		{"BackendStatus", func(ctx context.Context, tr *Transport) error {
			_, err := tr.BackendStatus(ctx, backend)
			return err
		}, "", ""},
		{"BackendTest", func(ctx context.Context, tr *Transport) error {
			_, err := tr.BackendTest(ctx, backend)
			return err
		}, "", ""},
		{"SetKeySafety", func(ctx context.Context, tr *Transport) error {
			_, err := tr.SetKeySafety(ctx, &transport.SetKeySafetyRequest{KeyID: "k"})
			return err
		}, "", ""},
		{"ClearKeySafety", func(ctx context.Context, tr *Transport) error {
			_, err := tr.ClearKeySafety(ctx, key)
			return err
		}, "", ""},
		{"SafetyCheck", func(ctx context.Context, tr *Transport) error {
			_, err := tr.SafetyCheck(ctx, &transport.SafetyCheckRequest{})
			return err
		}, "", ""},
		{"SafetyReport", func(ctx context.Context, tr *Transport) error {
			_, err := tr.SafetyReport(ctx, &transport.SafetyReportRequest{})
			return err
		}, "", ""},

		{"TrustRootList", func(ctx context.Context, tr *Transport) error {
			_, err := tr.TrustRootList(ctx, &transport.TrustRootListRequest{Purpose: "synced"})
			return err
		}, http.MethodGet, "/api/v1/trust-roots"},
		{"TrustRootGet", func(ctx context.Context, tr *Transport) error {
			_, err := tr.TrustRootGet(ctx, root)
			return err
		}, http.MethodGet, "/api/v1/trust-roots/ab12"},
		{"TrustRootImport", func(ctx context.Context, tr *Transport) error {
			_, err := tr.TrustRootImport(ctx, &transport.TrustRootImportRequest{PEM: "pem"})
			return err
		}, post, "/api/v1/trust-roots"},
		{"TrustRootQuarantine", func(ctx context.Context, tr *Transport) error {
			_, err := tr.TrustRootQuarantine(ctx, root)
			return err
		}, post, "/api/v1/trust-roots/ab12/quarantine"},
		{"TrustRootRemove", func(ctx context.Context, tr *Transport) error {
			return tr.TrustRootRemove(ctx, root)
		}, http.MethodDelete, "/api/v1/trust-roots/ab12"},

		{"ListSigningKeyBindings", func(ctx context.Context, tr *Transport) error {
			_, err := tr.ListSigningKeyBindings(ctx)
			return err
		}, http.MethodGet, "/api/v1/attestation/signing-keys"},
	}
}

// TestTransport_DelegatesSendOneRequest proves each crypto utility, key
// management and trust-root method of a connected transport sends exactly
// one request (to its route, where the route is pinned here) and surfaces
// a server error.
func TestTransport_DelegatesSendOneRequest(t *testing.T) {
	tr, rec := newWireTransport(t, http.StatusOK, `{}`)
	failing, _ := newWireTransport(t, http.StatusInternalServerError, `{"error":"backend unavailable"}`)
	ctx := context.Background()

	for _, c := range delegateCalls() {
		t.Run(c.name, func(t *testing.T) {
			require.NoError(t, c.call(ctx, tr))
			got := rec.take()
			require.Len(t, got, 1)
			if c.path != "" {
				assert.Equal(t, c.method, got[0].Method)
				assert.Equal(t, c.path, got[0].Path)
			}
			assert.Error(t, c.call(ctx, failing), "a server error is returned")
		})
	}
}

// TestTransport_DelegatesNotConnected proves no method sends a request
// before Connect.
func TestTransport_DelegatesNotConnected(t *testing.T) {
	tr := newDisconnected(t)
	for _, c := range delegateCalls() {
		t.Run(c.name, func(t *testing.T) {
			assert.ErrorIs(t, c.call(context.Background(), tr), ErrNotConnected)
		})
	}
}
