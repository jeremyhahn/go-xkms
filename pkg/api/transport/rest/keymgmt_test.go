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
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wire "github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// verbCase is one Transport verb that delegates to a wire client: the route
// it must reach, the reply the server sends and the answer decoded from it.
type verbCase struct {
	name  string
	route string
	reply string
	call  func(ctx context.Context, tr *Transport) (any, error)
	// checkBody asserts the request body the server received.
	checkBody func(t *testing.T, body []byte)
	want      any
}

// newVerbCase builds a verbCase for call(req). A verb that sends a body must
// send req itself; one that does not must send nothing.
func newVerbCase[Req, Resp any](
	name string,
	call func(*Transport, context.Context, *Req) (*Resp, error),
	req *Req,
	sendsBody bool,
	route, reply string,
	want *Resp,
) verbCase {
	return verbCase{
		name:  name,
		route: route,
		reply: reply,
		call: func(ctx context.Context, tr *Transport) (any, error) {
			return call(tr, ctx, req)
		},
		checkBody: func(t *testing.T, body []byte) {
			t.Helper()
			if !sendsBody {
				assert.Empty(t, body)
				return
			}
			var sent Req
			require.NoError(t, json.Unmarshal(body, &sent))
			assert.Equal(t, *req, sent)
		},
		want: want,
	}
}

// runVerbRoutes asserts every case reaches its route with its body and
// decodes every field of the server's answer.
func runVerbRoutes(t *testing.T, cases []verbCase) {
	t.Helper()
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := newRouteRecorder(t, http.StatusOK, tc.reply)
			resp, err := tc.call(ctx, rec.connect(t))
			require.NoError(t, err)
			req := rec.request(t)
			assert.Equal(t, tc.route, req.route)
			tc.checkBody(t, req.body)
			assert.Equal(t, tc.want, resp)
		})
	}
}

// runVerbErrors asserts every case fails with no answer when the transport
// is not connected, when the server refuses the request and when the
// server's answer is not JSON.
func runVerbErrors(t *testing.T, cases []verbCase) {
	t.Helper()
	ctx := context.Background()
	refusing := newRouteRecorder(t, http.StatusConflict, `{"error":"key is revoked"}`).connect(t)
	garbled := newRouteRecorder(t, http.StatusOK, `not json`).connect(t)

	for _, tc := range cases {
		t.Run(tc.name+"/not connected", func(t *testing.T) {
			resp, err := tc.call(ctx, &Transport{})
			assert.ErrorIs(t, err, ErrNotConnected)
			assert.Nil(t, resp)
		})

		t.Run(tc.name+"/server refusal", func(t *testing.T) {
			resp, err := tc.call(ctx, refusing)
			var msg *errs.Message
			require.ErrorAs(t, err, &msg)
			assert.Equal(t, "server error: key is revoked", msg.Msg)
			assert.Nil(t, resp)
		})

		t.Run(tc.name+"/unreadable reply", func(t *testing.T) {
			resp, err := tc.call(ctx, garbled)
			var decodeErr *wire.DecodeError
			assert.ErrorAs(t, err, &decodeErr)
			assert.Nil(t, resp)
		})
	}
}

func keyManagementCases() []verbCase {
	key := &transport.KeyManagementRequest{Backend: "pkcs#11", KeyID: "a b"}
	backend := &transport.BackendRequest{Backend: "pkcs#11"}
	deleted := &transport.KeyManagementResponse{KeyID: "a b", Timestamp: 9}
	deletedReply := `{"key_id":"a b","timestamp":9}`
	metadata := &transport.KeyMetadataResponse{
		Metadata:  &transport.KeyMetadata{KeyID: "a b", Name: "payments", Status: transport.KeyStatusEnabled},
		Timestamp: 9,
	}
	metadataReply := `{"metadata":{"key_id":"a b","name":"payments","status":"enabled"},"timestamp":9}`
	rotation := &transport.KeyRotationPolicyResponse{
		KeyID:     "a b",
		Policy:    &transport.RotationPolicy{Enabled: true, IntervalSeconds: 86400},
		Timestamp: 9,
	}
	rotationReply := `{"key_id":"a b","policy":{"enabled":true,"interval_seconds":86400},"timestamp":9}`

	return []verbCase{
		newVerbCase("GetPublicKey", (*Transport).GetPublicKey,
			&transport.GetPublicKeyRequest{Backend: "pkcs#11", KeyID: "a b", Version: 2}, false,
			"GET /api/v1/keys/a%20b/public-key?backend=pkcs%2311&version=2",
			`{"key_id":"a b","public_key":"AQI=","algorithm":"AES-256-GCM","version":2,"timestamp":9}`,
			&transport.GetPublicKeyResponse{KeyID: "a b", PublicKey: []byte{1, 2}, Algorithm: transport.KeyAlgorithmAES256GCM, Version: 2, Timestamp: 9}),
		newVerbCase("RevokeKey", (*Transport).RevokeKey,
			&transport.RevokeKeyRequest{Backend: "pkcs#11", KeyID: "a b", Reason: "lost"}, true,
			"POST /api/v1/keys/a%20b/revoke",
			`{"key_id":"a b","status":"deleted","timestamp":9}`,
			&transport.RevokeKeyResponse{KeyID: "a b", Status: transport.KeyStatusDeleted, Timestamp: 9}),
		newVerbCase("UpdateKeyStatus", (*Transport).UpdateKeyStatus,
			&transport.UpdateKeyStatusRequest{Backend: "pkcs#11", KeyID: "a b", Version: 3, Status: transport.KeyStatusDisabled}, true,
			"POST /api/v1/keys/a%20b/status",
			`{"key_id":"a b","version":3,"status":"disabled","timestamp":9}`,
			&transport.UpdateKeyStatusResponse{KeyID: "a b", Version: 3, Status: transport.KeyStatusDisabled, Timestamp: 9}),
		newVerbCase("GetKeyMetadata", (*Transport).GetKeyMetadata, key, false,
			"GET /api/v1/keys/a%20b/metadata?backend=pkcs%2311", metadataReply, metadata),
		newVerbCase("UpdateKeyMetadata", (*Transport).UpdateKeyMetadata,
			&transport.UpdateKeyMetadataRequest{Backend: "pkcs#11", KeyID: "a b", Name: "payments", Tags: map[string]string{"env": "prod"}, RemoveTags: []string{"tmp"}}, true,
			"PUT /api/v1/keys/a%20b/metadata", metadataReply, metadata),
		newVerbCase("SetKeyPolicy", (*Transport).SetKeyPolicy,
			&transport.SetKeyPolicyRequest{Backend: "pkcs#11", KeyID: "a b", Policy: &transport.KeyPolicy{AllowedPrincipals: []string{"svc"}, ExpiresAt: 100}}, true,
			"PUT /api/v1/keys/a%20b/policy",
			`{"key_id":"a b","policy_version":4,"timestamp":9}`,
			&transport.SetKeyPolicyResponse{KeyID: "a b", PolicyVersion: 4, Timestamp: 9}),
		newVerbCase("GetKeyPolicy", (*Transport).GetKeyPolicy, key, false,
			"GET /api/v1/keys/a%20b/policy?backend=pkcs%2311",
			`{"policy":{"key_id":"a b","version":4,"denied_principals":["guest"]},"timestamp":9}`,
			&transport.GetKeyPolicyResponse{Policy: &transport.KeyPolicy{KeyID: "a b", Version: 4, DeniedPrincipals: []string{"guest"}}, Timestamp: 9}),
		newVerbCase("DeleteKeyPolicy", (*Transport).DeleteKeyPolicy, key, false,
			"DELETE /api/v1/keys/a%20b/policy?backend=pkcs%2311", deletedReply, deleted),
		newVerbCase("SetKeyRotationPolicy", (*Transport).SetKeyRotationPolicy,
			&transport.SetKeyRotationPolicyRequest{Backend: "pkcs#11", KeyID: "a b", Policy: &transport.RotationPolicy{Enabled: true, IntervalSeconds: 86400}}, true,
			"PUT /api/v1/keys/a%20b/rotation-policy", rotationReply, rotation),
		newVerbCase("GetKeyRotationPolicy", (*Transport).GetKeyRotationPolicy, key, false,
			"GET /api/v1/keys/a%20b/rotation-policy?backend=pkcs%2311", rotationReply, rotation),
		newVerbCase("DeleteKeyRotationPolicy", (*Transport).DeleteKeyRotationPolicy, key, false,
			"DELETE /api/v1/keys/a%20b/rotation-policy?backend=pkcs%2311", deletedReply, deleted),
		newVerbCase("GetSupportedAlgorithms", (*Transport).GetSupportedAlgorithms, backend, false,
			"GET /api/v1/backend/algorithms?backend=pkcs%2311",
			`{"algorithms":["AES-128-GCM","ChaCha20-Poly1305"]}`,
			&transport.GetSupportedAlgorithmsResponse{Algorithms: []transport.KeyAlgorithm{transport.KeyAlgorithmAES128GCM, transport.KeyAlgorithmChaCha20Poly1305}}),
		newVerbCase("BackendStatus", (*Transport).BackendStatus, backend, false,
			"GET /api/v1/backend/status?backend=pkcs%2311",
			`{"backend_type":"pkcs11","status":"healthy","device":"slot0","pcr_banks":["sha256"],"pcr_registers":[7],"capabilities":{"sign":true}}`,
			&transport.BackendStatusResponse{BackendType: "pkcs11", Status: "healthy", Device: "slot0", PCRBanks: []string{"sha256"}, PCRRegisters: []int32{7}, Capabilities: map[string]bool{"sign": true}}),
		newVerbCase("BackendTest", (*Transport).BackendTest, backend, true,
			"POST /api/v1/backend/test",
			`{"success":true,"duration_ms":12,"message":"round trip ok","timestamp":9}`,
			&transport.BackendTestResponse{Success: true, DurationMS: 12, Message: "round trip ok", Timestamp: 9}),
		newVerbCase("SetKeySafety", (*Transport).SetKeySafety,
			&transport.SetKeySafetyRequest{Backend: "pkcs#11", KeyID: "a b", MaxOperations: 10, MaxBytes: 4096, WarningPercent: 80}, true,
			"PUT /api/v1/keys/a%20b/safety", deletedReply, deleted),
		newVerbCase("ClearKeySafety", (*Transport).ClearKeySafety, key, false,
			"DELETE /api/v1/keys/a%20b/safety?backend=pkcs%2311", deletedReply, deleted),
		newVerbCase("SafetyCheck", (*Transport).SafetyCheck, &transport.SafetyCheckRequest{}, false,
			"GET /api/v1/safety/check",
			`{"warnings":[{"type":"key","path":"a b","usage_percent":91.5,"status":"warning","operations_used":9,"bytes_used":0,"max_operations":10}],"timestamp":9}`,
			&transport.SafetyCheckResponse{Warnings: []transport.SafetyWarning{{Type: "key", Path: "a b", UsagePercent: 91.5, Status: "warning", OperationsUsed: 9, MaxOperations: 10}}, Timestamp: 9}),
		newVerbCase("SafetyReport", (*Transport).SafetyReport, &transport.SafetyReportRequest{Format: "table"}, false,
			"GET /api/v1/safety/report?format=table",
			`{"all_items":[],"total_keys":3,"total_deks":2,"keys_at_warning":1,"keys_at_critical":1,"deks_at_warning":1,"deks_at_critical":0,"timestamp":9}`,
			&transport.SafetyReportResponse{AllItems: []transport.SafetyWarning{}, TotalKeys: 3, TotalDEKs: 2, KeysAtWarning: 1, KeysAtCritical: 1, DEKsAtWarning: 1, Timestamp: 9}),
	}
}

func TestKeyManagementVerbs_Routes(t *testing.T) {
	runVerbRoutes(t, keyManagementCases())
}

func TestKeyManagementVerbs_Errors(t *testing.T) {
	runVerbErrors(t, keyManagementCases())
}
