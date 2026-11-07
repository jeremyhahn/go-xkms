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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

func trustRootCases() []verbCase {
	root := &transport.TrustRootRequest{Fingerprint: "ab/cd"}
	quarantined := &transport.TrustRoot{Fingerprint: "ab/cd", Purpose: "synced", Subject: "CN=Root", Issuer: "CN=Root", Algorithm: "ECDSA"}
	quarantinedReply := `{"fingerprint":"ab/cd","purpose":"synced","subject":"CN=Root","issuer":"CN=Root","algorithm":"ECDSA"}`

	return []verbCase{
		newVerbCase("TrustRootList", (*Transport).TrustRootList,
			&transport.TrustRootListRequest{Purpose: "user-ca"}, false,
			"GET /api/v1/trust-roots?purpose=user-ca",
			`{"roots":[{"fingerprint":"ab","purpose":"user-ca","subject":"CN=A","issuer":"CN=A","algorithm":"RSA"}]}`,
			&transport.TrustRootListResponse{Roots: []transport.TrustRoot{{Fingerprint: "ab", Purpose: "user-ca", Subject: "CN=A", Issuer: "CN=A", Algorithm: "RSA"}}}),
		newVerbCase("TrustRootGet", (*Transport).TrustRootGet, root, false,
			"GET /api/v1/trust-roots/ab%2Fcd", quarantinedReply, quarantined),
		newVerbCase("TrustRootImport", (*Transport).TrustRootImport,
			&transport.TrustRootImportRequest{PEM: "-----BEGIN CERTIFICATE-----", Purpose: "general"}, true,
			"POST /api/v1/trust-roots",
			`{"added":2,"skipped":1}`,
			&transport.TrustRootImportResponse{Added: 2, Skipped: 1}),
		newVerbCase("TrustRootQuarantine", (*Transport).TrustRootQuarantine, root, false,
			"POST /api/v1/trust-roots/ab%2Fcd/quarantine", quarantinedReply, quarantined),
	}
}

func TestTrustRootVerbs_Routes(t *testing.T) {
	runVerbRoutes(t, trustRootCases())
}

func TestTrustRootVerbs_Errors(t *testing.T) {
	runVerbErrors(t, trustRootCases())
}

// TestTrustRootRemove proves the removal deletes the root by its escaped
// fingerprint and surfaces a refusal, and that an unconnected transport
// sends nothing.
func TestTrustRootRemove(t *testing.T) {
	ctx := context.Background()
	req := &transport.TrustRootRequest{Fingerprint: "ab/cd"}

	removed := newRouteRecorder(t, http.StatusNoContent, ``)
	require.NoError(t, removed.connect(t).TrustRootRemove(ctx, req))
	sent := removed.request(t)
	assert.Equal(t, "DELETE /api/v1/trust-roots/ab%2Fcd", sent.route)
	assert.Empty(t, sent.body)

	refused := newRouteRecorder(t, http.StatusNotFound, `{"error":"no such root"}`)
	var msg *errs.Message
	require.ErrorAs(t, refused.connect(t).TrustRootRemove(ctx, req), &msg)
	assert.Equal(t, "server error: no such root", msg.Msg)

	assert.ErrorIs(t, (&Transport{}).TrustRootRemove(ctx, req), ErrNotConnected)
}
