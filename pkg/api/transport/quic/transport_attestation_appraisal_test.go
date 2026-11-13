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

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/appraisaltest"
)

// TestAttestationAppraisal_RefusesANilRequest proves a connected transport
// hands its calls to the wire client, which refuses a nil request.
func TestAttestationAppraisal_RefusesANilRequest(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	for name, call := range appraisaltest.NilRequestCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), wire.ErrNilRequest) })
	}
}

// TestAttestationAppraisal_NotConnected proves every Verifier method refuses
// before the transport is connected.
func TestAttestationAppraisal_NotConnected(t *testing.T) {
	for name, call := range appraisaltest.Calls(context.Background(), newDisconnected(t)) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}

// TestAttestationAppraisal_ListReferenceValues checks the connected transport
// lists stored reference values from the server and surfaces a server failure.
func TestAttestationAppraisal_ListReferenceValues(t *testing.T) {
	tr, rec := newWireTransport(t, http.StatusOK, `{"reference_values":[{"name":"fw","manifest_id":"m1"}]}`)
	resp, err := tr.ListAttestationReferenceValues(context.Background())
	require.NoError(t, err)
	got := rec.take()
	require.Len(t, got, 1)
	assert.Equal(t, http.MethodGet, got[0].Method)
	assert.Equal(t, "/api/v1/attestation/reference-values", got[0].Path)
	require.Len(t, resp.ReferenceValues, 1)
	assert.Equal(t, "fw", resp.ReferenceValues[0].Name)
	assert.Equal(t, "m1", resp.ReferenceValues[0].ManifestID)

	failing, _ := newWireTransport(t, http.StatusInternalServerError, `{"error":"store unavailable"}`)
	_, err = failing.ListAttestationReferenceValues(context.Background())
	assert.Error(t, err)
}
