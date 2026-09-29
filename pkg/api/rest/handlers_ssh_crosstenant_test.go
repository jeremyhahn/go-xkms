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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/tenancy"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ===========================================================================
// SSH owner binding over REST (go-xkms#1230).
//
// The SSH routes take scope and owner from the request. A tenant-scoped
// caller may address only its own tenant's scope=tenant assets and only its
// own scope=user assets; everything else must answer exactly as a missing
// asset does, so a probe learns nothing. Side effects are asserted too: a
// handler that answered 404 after deleting the key would still be a breach.
// ===========================================================================

const (
	sshTenantA = "tenant-a"
	sshTenantB = "tenant-b"
)

var (
	sshAliceA   = &auth.Identity{Subject: "alice", TenantID: sshTenantA}
	sshBobA     = &auth.Identity{Subject: "bob", TenantID: sshTenantA}
	sshAdminB   = &auth.Identity{Subject: "b-admin", TenantID: sshTenantB}
	sshAliceB   = &auth.Identity{Subject: "alice", TenantID: sshTenantB}
	sshPlatform = &auth.Identity{Subject: "root", TenantID: qrdbsdk.SystemTenantID}
)

// sshAs returns a context carrying id.
func sshAs(id *auth.Identity) context.Context {
	return auth.WithIdentity(context.Background(), id)
}

// newSSHTenancyClient builds the SSH client xkmsd wires into every transport,
// over empty in-memory storage.
func newSSHTenancyClient(t *testing.T) sdkssh.Client {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	client, err := tenancy.New(tenancy.Options{Storage: backend})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	return client
}

// sshTestPublicLine returns a fresh ed25519 public key as an authorized_keys
// line.
func sshTestPublicLine(t *testing.T) string {
	t.Helper()
	_, line := sshTestSigner(t)
	return line
}

// sshTestPrivatePEM returns a fresh unencrypted OpenSSH private key PEM.
func sshTestPrivatePEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := gossh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	return pem.EncodeToMemory(block)
}

// seedSSHOwners stores, each through its rightful owner, one asset of every
// kind the attacks below aim at: tenant B's key, authorized_keys entry and
// known-hosts pin; bob's (tenant A) key and authorized entry; and the key of
// alice in tenant B, who shares a subject with the attacker.
func seedSSHOwners(t *testing.T, client sdkssh.Client) {
	t.Helper()
	gen := func(id *auth.Identity, scope, owner, name string) {
		_, err := client.Keys().Generate(sshAs(id), sdkssh.GenerateRequest{
			Scope: scope, Owner: owner, Name: name, Algorithm: "ed25519",
		})
		require.NoError(t, err, "seeding %s/%s/%s", scope, owner, name)
	}
	gen(sshAdminB, "tenant", sshTenantB, "b-key")
	gen(sshBobA, "user", "bob", "bob-key")
	gen(sshAliceB, "user", "alice", "alice-b-key")

	require.NoError(t, client.AuthorizedKeys().Add(sshAs(sshAdminB), sdkssh.AddAuthorizedKeyRequest{
		Scope: "tenant", Owner: sshTenantB, Name: "b-entry", Line: sshTestPublicLine(t),
	}))
	require.NoError(t, client.AuthorizedKeys().Add(sshAs(sshBobA), sdkssh.AddAuthorizedKeyRequest{
		Scope: "user", Owner: "bob", Name: "bob-entry", Line: sshTestPublicLine(t),
	}))
	require.NoError(t, client.KnownHosts().Add(sshAs(sshAdminB), sdkssh.AddKnownHostRequest{
		Scope: "tenant", Owner: sshTenantB, Host: "b.example.com", PublicKey: sshTestPublicLine(t),
	}))
}

// sshRESTRouter mounts the SSH routes over client.
func sshRESTRouter(t *testing.T, client sdkssh.Client) http.Handler {
	t.Helper()
	h, err := NewSSHHandlers(client, nil)
	require.NoError(t, err)
	r := chi.NewRouter()
	h.Register(r)
	return r
}

// sshRESTCall serves one request as id and returns the status and body.
func sshRESTCall(t *testing.T, router http.Handler, id *auth.Identity, method, path string, body interface{}) (int, string) {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, reader).WithContext(sshAs(id))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// sshRESTAttack is one request tenant A's alice sends at an asset she does
// not own.
type sshRESTAttack struct {
	name   string
	method string
	path   string
	body   interface{}
}

// sshRESTReadAttacks address existing assets of tenant B, of bob, and of
// alice in tenant B. Each must answer exactly as the same request does when
// the asset does not exist.
func sshRESTReadAttacks() []sshRESTAttack {
	digest := map[string][]byte{"digest": []byte("payload")}
	return []sshRESTAttack{
		{"tenant get key", http.MethodGet, "/xkms/v1/ssh/keys/tenant/" + sshTenantB + "/b-key", nil},
		{"tenant export public", http.MethodGet, "/xkms/v1/ssh/keys/tenant/" + sshTenantB + "/b-key/public", nil},
		{"tenant sign", http.MethodPost, "/xkms/v1/ssh/keys/tenant/" + sshTenantB + "/b-key/sign", digest},
		{"tenant delete key", http.MethodDelete, "/xkms/v1/ssh/keys/tenant/" + sshTenantB + "/b-key", nil},
		{"tenant get authorized", http.MethodGet, "/xkms/v1/ssh/authorized-keys/tenant/" + sshTenantB + "/b-entry", nil},
		{"tenant remove authorized", http.MethodDelete, "/xkms/v1/ssh/authorized-keys/tenant/" + sshTenantB + "/b-entry", nil},
		{"tenant remove known host", http.MethodDelete, "/xkms/v1/ssh/known-hosts/b.example.com?scope=tenant&owner=" + sshTenantB, nil},
		{"user get key", http.MethodGet, "/xkms/v1/ssh/keys/user/bob/bob-key", nil},
		{"user export public", http.MethodGet, "/xkms/v1/ssh/keys/user/bob/bob-key/public", nil},
		{"user sign", http.MethodPost, "/xkms/v1/ssh/keys/user/bob/bob-key/sign", digest},
		{"user delete key", http.MethodDelete, "/xkms/v1/ssh/keys/user/bob/bob-key", nil},
		{"user get authorized", http.MethodGet, "/xkms/v1/ssh/authorized-keys/user/bob/bob-entry", nil},
		{"user remove authorized", http.MethodDelete, "/xkms/v1/ssh/authorized-keys/user/bob/bob-entry", nil},
		{"same subject other tenant get key", http.MethodGet, "/xkms/v1/ssh/keys/user/alice/alice-b-key", nil},
		{"same subject other tenant sign", http.MethodPost, "/xkms/v1/ssh/keys/user/alice/alice-b-key/sign", digest},
		{"same subject other tenant delete key", http.MethodDelete, "/xkms/v1/ssh/keys/user/alice/alice-b-key", nil},
	}
}

// TestSSHREST_CrossOwnerReadsAnswerAsMissing proves every by-name SSH route
// refuses another owner's asset with the byte-identical response a missing
// asset gets, and leaves the asset in place.
func TestSSHREST_CrossOwnerReadsAnswerAsMissing(t *testing.T) {
	for _, tc := range sshRESTReadAttacks() {
		t.Run(tc.name, func(t *testing.T) {
			seeded := newSSHTenancyClient(t)
			seedSSHOwners(t, seeded)
			empty := newSSHTenancyClient(t)

			gotStatus, gotBody := sshRESTCall(t, sshRESTRouter(t, seeded), sshAliceA, tc.method, tc.path, tc.body)
			missStatus, missBody := sshRESTCall(t, sshRESTRouter(t, empty), sshAliceA, tc.method, tc.path, tc.body)

			assert.Equal(t, http.StatusNotFound, missStatus, "control: the empty deployment must answer 404")
			assert.Equal(t, missStatus, gotStatus, "another owner's asset must answer as a missing one")
			assert.Equal(t, missBody, gotBody, "the refusal body must be the genuine-miss body")
			requireSSHOwnersIntact(t, seeded)
		})
	}
}

// TestSSHREST_CrossOwnerListsHideForeignAssets proves no listing, with or
// without scope/owner filters, returns an asset alice does not own.
func TestSSHREST_CrossOwnerListsHideForeignAssets(t *testing.T) {
	client := newSSHTenancyClient(t)
	seedSSHOwners(t, client)
	router := sshRESTRouter(t, client)

	paths := []string{
		"/xkms/v1/ssh/keys?scope=tenant&owner=" + sshTenantB,
		"/xkms/v1/ssh/keys?scope=user&owner=bob",
		"/xkms/v1/ssh/keys?scope=user&owner=alice",
		"/xkms/v1/ssh/keys",
		"/xkms/v1/ssh/authorized-keys?scope=tenant&owner=" + sshTenantB,
		"/xkms/v1/ssh/authorized-keys?scope=user&owner=bob",
		"/xkms/v1/ssh/authorized-keys",
		"/xkms/v1/ssh/known-hosts?scope=tenant&owner=" + sshTenantB,
		"/xkms/v1/ssh/known-hosts",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			status, body := sshRESTCall(t, router, sshAliceA, http.MethodGet, path, nil)
			require.Equal(t, http.StatusOK, status, body)
			var list struct {
				Items []json.RawMessage `json:"items"`
			}
			require.NoError(t, json.Unmarshal([]byte(body), &list))
			assert.Empty(t, list.Items, "alice must see no asset she does not own")
		})
	}
}

// TestSSHREST_CrossOwnerWritesRefused proves alice cannot create a key,
// import a key, authorize a key or pin a host under another owner, that the
// refusal is the not-found answer, and that nothing lands for that owner.
func TestSSHREST_CrossOwnerWritesRefused(t *testing.T) {
	attacks := []sshRESTAttack{
		{"generate tenant", http.MethodPost, "/xkms/v1/ssh/keys",
			sdkssh.GenerateRequest{Scope: "tenant", Owner: sshTenantB, Name: "planted", Algorithm: "ed25519"}},
		{"generate user", http.MethodPost, "/xkms/v1/ssh/keys",
			sdkssh.GenerateRequest{Scope: "user", Owner: "bob", Name: "planted", Algorithm: "ed25519"}},
		{"add authorized tenant", http.MethodPost, "/xkms/v1/ssh/authorized-keys",
			sdkssh.AddAuthorizedKeyRequest{Scope: "tenant", Owner: sshTenantB, Name: "planted", Line: sshTestPublicLine(t)}},
		{"add authorized user", http.MethodPost, "/xkms/v1/ssh/authorized-keys",
			sdkssh.AddAuthorizedKeyRequest{Scope: "user", Owner: "bob", Name: "planted", Line: sshTestPublicLine(t)}},
		{"add known host tenant", http.MethodPost, "/xkms/v1/ssh/known-hosts",
			sdkssh.AddKnownHostRequest{Scope: "tenant", Owner: sshTenantB, Host: "planted.example.com", PublicKey: sshTestPublicLine(t)}},
	}
	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			client := newSSHTenancyClient(t)
			router := sshRESTRouter(t, client)
			status, body := sshRESTCall(t, router, sshAliceA, tc.method, tc.path, tc.body)
			assert.Equal(t, http.StatusNotFound, status, body)
			requireNothingPlanted(t, client)
		})
	}

	t.Run("import tenant", func(t *testing.T) {
		client := newSSHTenancyClient(t)
		router := sshRESTRouter(t, client)
		status, body := sshRESTCall(t, router, sshAliceA, http.MethodPost, "/xkms/v1/ssh/keys/import",
			map[string]interface{}{"scope": "tenant", "owner": sshTenantB, "name": "planted", "pem": sshTestPrivatePEM(t)})
		assert.Equal(t, http.StatusNotFound, status, body)
		requireNothingPlanted(t, client)
	})
}

// TestSSHREST_KnownHostVerifyCrossOwner proves verifying a presented host key
// against another owner's pin answers as a missing pin.
func TestSSHREST_KnownHostVerifyCrossOwner(t *testing.T) {
	seeded := newSSHTenancyClient(t)
	seedSSHOwners(t, seeded)
	pins, err := seeded.KnownHosts().List(sshAs(sshAdminB), sdkssh.ListKnownHostsRequest{Scope: "tenant", Owner: sshTenantB})
	require.NoError(t, err)
	require.Len(t, pins, 1)
	body := map[string]string{"scope": "tenant", "owner": sshTenantB, "public_key": pins[0].PublicKey}
	path := "/xkms/v1/ssh/known-hosts/b.example.com/verify"

	gotStatus, gotBody := sshRESTCall(t, sshRESTRouter(t, seeded), sshAliceA, http.MethodPost, path, body)
	missStatus, missBody := sshRESTCall(t, sshRESTRouter(t, newSSHTenancyClient(t)), sshAliceA, http.MethodPost, path, body)

	assert.Equal(t, http.StatusNotFound, missStatus)
	assert.Equal(t, missStatus, gotStatus, "verify against a foreign pin must answer as a missing pin")
	assert.Equal(t, missBody, gotBody)
}

// TestSSHREST_OwnersKeepAccess is the positive control: a check that refused
// everything would satisfy every test above. Each owner reaches its own
// assets, and a platform identity reaches tenant B's.
func TestSSHREST_OwnersKeepAccess(t *testing.T) {
	client := newSSHTenancyClient(t)
	seedSSHOwners(t, client)
	router := sshRESTRouter(t, client)
	digest := map[string][]byte{"digest": []byte("payload")}

	cases := []struct {
		name   string
		id     *auth.Identity
		method string
		path   string
		body   interface{}
		want   int
	}{
		{"tenant B signs with its key", sshAdminB, http.MethodPost, "/xkms/v1/ssh/keys/tenant/" + sshTenantB + "/b-key/sign", digest, http.StatusOK},
		{"bob signs with his key", sshBobA, http.MethodPost, "/xkms/v1/ssh/keys/user/bob/bob-key/sign", digest, http.StatusOK},
		{"alice of tenant B reads her key", sshAliceB, http.MethodGet, "/xkms/v1/ssh/keys/user/alice/alice-b-key", nil, http.StatusOK},
		{"platform reads tenant B's key", sshPlatform, http.MethodGet, "/xkms/v1/ssh/keys/tenant/" + sshTenantB + "/b-key", nil, http.StatusOK},
		{"platform reads tenant B's authorized entry", sshPlatform, http.MethodGet, "/xkms/v1/ssh/authorized-keys/tenant/" + sshTenantB + "/b-entry", nil, http.StatusOK},
		{"alice creates a tenant A key", sshAliceA, http.MethodPost, "/xkms/v1/ssh/keys",
			sdkssh.GenerateRequest{Scope: "tenant", Owner: sshTenantA, Name: "a-key", Algorithm: "ed25519"}, http.StatusCreated},
		{"alice creates her own key", sshAliceA, http.MethodPost, "/xkms/v1/ssh/keys",
			sdkssh.GenerateRequest{Scope: "user", Owner: "alice", Name: "alice-a-key", Algorithm: "ed25519"}, http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := sshRESTCall(t, router, tc.id, tc.method, tc.path, tc.body)
			assert.Equal(t, tc.want, status, body)
		})
	}

	// Tenant B's listing shows exactly its own key, and alice's shows only
	// the two she created -- never alice-b-key, which shares her subject.
	status, body := sshRESTCall(t, router, sshAdminB, http.MethodGet, "/xkms/v1/ssh/keys?scope=tenant&owner="+sshTenantB, nil)
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, `"b-key"`)
	status, body = sshRESTCall(t, router, sshAliceA, http.MethodGet, "/xkms/v1/ssh/keys", nil)
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, `"a-key"`)
	assert.Contains(t, body, `"alice-a-key"`)
	assert.NotContains(t, body, "alice-b-key")
	assert.NotContains(t, body, "bob-key")
	assert.NotContains(t, body, `"b-key"`)
}

// requireSSHOwnersIntact proves every seeded asset survived, each read back
// through its owner.
func requireSSHOwnersIntact(t *testing.T, client sdkssh.Client) {
	t.Helper()
	_, err := client.Keys().Get(sshAs(sshAdminB), sdkssh.GetKeyRequest{Scope: "tenant", Owner: sshTenantB, Name: "b-key"})
	require.NoError(t, err, "tenant B lost its key")
	_, err = client.Keys().Get(sshAs(sshBobA), sdkssh.GetKeyRequest{Scope: "user", Owner: "bob", Name: "bob-key"})
	require.NoError(t, err, "bob lost his key")
	_, err = client.Keys().Get(sshAs(sshAliceB), sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "alice-b-key"})
	require.NoError(t, err, "alice of tenant B lost her key")
	_, err = client.AuthorizedKeys().Get(sshAs(sshAdminB), "tenant", sshTenantB, "b-entry")
	require.NoError(t, err, "tenant B lost its authorized entry")
	_, err = client.AuthorizedKeys().Get(sshAs(sshBobA), "user", "bob", "bob-entry")
	require.NoError(t, err, "bob lost his authorized entry")
	pins, err := client.KnownHosts().List(sshAs(sshAdminB), sdkssh.ListKnownHostsRequest{Scope: "tenant", Owner: sshTenantB})
	require.NoError(t, err)
	require.Len(t, pins, 1, "tenant B lost its known-hosts pin")
}

// requireNothingPlanted proves no refused write landed, read back as every
// owner an attack could have planted under.
func requireNothingPlanted(t *testing.T, client sdkssh.Client) {
	t.Helper()
	for _, owner := range []*auth.Identity{sshAdminB, sshBobA, sshPlatform} {
		ctx := sshAs(owner)
		keys, err := client.Keys().List(ctx, sdkssh.ListKeysRequest{})
		require.NoError(t, err)
		assert.Empty(t, keys, "a key was planted for %s", owner.Subject)
		entries, err := client.AuthorizedKeys().List(ctx, sdkssh.ListAuthorizedKeysRequest{})
		require.NoError(t, err)
		assert.Empty(t, entries, "an authorized entry was planted for %s", owner.Subject)
		pins, err := client.KnownHosts().List(ctx, sdkssh.ListKnownHostsRequest{})
		require.NoError(t, err)
		for _, p := range pins {
			assert.False(t, strings.HasPrefix(p.Host, "planted"), "a pin was planted for %s", owner.Subject)
		}
	}
}
