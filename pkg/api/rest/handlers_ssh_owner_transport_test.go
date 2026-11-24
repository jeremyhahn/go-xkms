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
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// sshTokenAuth stands in for xkmsd's bearer authentication: a known stub
// token puts its identity into the request context, anything else answers
// 401 without reaching the router. It records every admitted escaped path.
type sshTokenAuth struct {
	next   http.Handler
	tokens map[string]*auth.Identity

	mu    sync.Mutex
	paths []string
}

func (a *sshTokenAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, ok := a.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	if !ok || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	a.mu.Lock()
	a.paths = append(a.paths, r.URL.EscapedPath())
	a.mu.Unlock()
	a.next.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), id)))
}

func (a *sshTokenAuth) admitted() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.paths...)
}

// TestSSHREST_OmittedOwnerThroughSDKTransport drives the in-tree SDK REST
// client against the tenancy-backed handlers behind bearer authentication:
// an omitted user owner travels as an empty path segment
// (/keys/user//laptop/...), survives routing and authentication, and
// resolves to the caller's own key on the server, never another caller's.
func TestSSHREST_OmittedOwnerThroughSDKTransport(t *testing.T) {
	client := newSSHTenancyClient(t)
	seedSSHOwners(t, client)
	aliceKey, err := client.Keys().Generate(sshAs(sshAliceA), sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "laptop", Algorithm: "ed25519",
	})
	require.NoError(t, err)

	mw := &sshTokenAuth{
		next:   sshRESTRouter(t, client),
		tokens: map[string]*auth.Identity{"alice-token": sshAliceA, "bob-token": sshBobA},
	}
	srv := httptest.NewServer(mw)
	t.Cleanup(srv.Close)

	sdkAs := func(token string) sdkssh.Client {
		c, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL, HTTPClient: srv.Client(), AuthToken: token})
		require.NoError(t, err)
		return c
	}
	ctx := context.Background()
	alice := sdkAs("alice-token")

	pub, err := alice.Keys().ExportPublic(ctx, sdkssh.ExportRequest{Scope: "user", Name: "laptop"})
	require.NoError(t, err)
	assert.Equal(t, aliceKey.Fingerprint, pub.Fingerprint)
	assert.Equal(t, strings.TrimSpace(aliceKey.PublicKey), strings.TrimSpace(pub.Line))

	signer, err := alice.Keys().Signer(ctx, sdkssh.GetKeyRequest{Scope: "user", Name: "laptop"})
	require.NoError(t, err)
	data := make([]byte, 64)
	_, err = rand.Read(data)
	require.NoError(t, err)
	sig, err := signer.Sign(rand.Reader, data)
	require.NoError(t, err)
	stored, _, _, _, err := gossh.ParseAuthorizedKey([]byte(aliceKey.PublicKey))
	require.NoError(t, err)
	require.NoError(t, stored.Verify(data, sig), "remote signature verifies with alice's generated key")

	paths := mw.admitted()
	assert.Contains(t, paths, "/xkms/v1/ssh/keys/user//laptop/public")
	assert.Contains(t, paths, "/xkms/v1/ssh/keys/user//laptop/sign")

	// An omitted owner never reaches another caller's key.
	_, err = alice.Keys().ExportPublic(ctx, sdkssh.ExportRequest{Scope: "user", Name: "bob-key"})
	assert.Error(t, err, "alice with no owner must not export bob's key")
	_, err = alice.Keys().Signer(ctx, sdkssh.GetKeyRequest{Scope: "user", Name: "bob-key"})
	assert.Error(t, err, "alice with no owner must not sign with bob's key")

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/xkms/v1/ssh/keys/user//bob-key/sign",
		strings.NewReader(`{"digest":"AAAA"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer alice-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.False(t, resp.StatusCode >= 200 && resp.StatusCode < 300,
		"raw sign of bob's key as alice answered %d", resp.StatusCode)

	_, err = sdkAs("bob-token").Keys().ExportPublic(ctx, sdkssh.ExportRequest{Scope: "user", Name: "laptop"})
	assert.Error(t, err, "bob with no owner must not export alice's laptop key")
	_, err = sdkAs("bob-token").Keys().Signer(ctx, sdkssh.GetKeyRequest{Scope: "user", Name: "laptop"})
	assert.Error(t, err, "bob with no owner must not sign with alice's laptop key")

	_, err = sdkAs("").Keys().ExportPublic(ctx, sdkssh.ExportRequest{Scope: "user", Name: "laptop"})
	assert.Error(t, err, "no token is refused by authentication")
}
