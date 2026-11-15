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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/signingkeytest"
)

// TestSigningKey_RefusesANilRequest proves a connected transport hands its
// calls to the wire client, which refuses a nil request.
func TestSigningKey_RefusesANilRequest(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	_, err := tr.ResolveSigningKey(context.Background(), nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	assert.ErrorIs(t, tr.DeleteSigningKeyBinding(context.Background(), nil), wire.ErrNilRequest)
	_, err = tr.SetSigningKeyBinding(context.Background(), nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	_, err = tr.GetSigningKeyBinding(context.Background(), nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
}

// TestSigningKey_NotConnected proves every signing-key method refuses
// before the transport is connected.
func TestSigningKey_NotConnected(t *testing.T) {
	for name, call := range signingkeytest.Calls(context.Background(), newDisconnected(t)) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}

// TestReleaseSigning_ReachesTheSignRoute signs through the QUIC client over
// the REST wire contract (the HTTP/3 listener serves the REST router, whose
// sign handler pkg/api/rest tests against the real service; this package
// cannot import pkg/auth, an import cycle through pkg/pkcs11/module).
func TestReleaseSigning_ReachesTheSignRoute(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+wire.SigningKeySignPath, func(w http.ResponseWriter, r *http.Request) {
		var req transport.SignReleaseCoRIMRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, signingkeytest.Repository, req.Repository)
		_ = json.NewEncoder(w).Encode(transport.SignReleaseCoRIMResponse{SignedCoRIM: append([]byte("signed:"), req.CoRIM...), KeyID: "release-signing"})
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	tr := &Transport{config: transport.DefaultConfig(), httpClient: srv.Client(), baseURL: srv.URL, connected: true}

	resp, err := tr.SignReleaseCoRIM(context.Background(), &transport.SignReleaseCoRIMRequest{Repository: signingkeytest.Repository, CoRIM: []byte{0xa0}})
	require.NoError(t, err)
	assert.Equal(t, []byte("signed:\xa0"), resp.SignedCoRIM)
	assert.Equal(t, "release-signing", resp.KeyID)

	_, err = tr.SignReleaseCoRIM(context.Background(), nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
}
