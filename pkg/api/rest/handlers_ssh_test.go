// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	gossh "golang.org/x/crypto/ssh"

	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// Mock SDK SSH client
// -----------------------------------------------------------------------------

type mockSSHClient struct {
	keys *mockKeysClient
	kh   *mockKnownHostsClient
	ak   *mockAuthorizedKeysClient
}

func (m *mockSSHClient) Keys() sdkssh.KeysClient                     { return m.keys }
func (m *mockSSHClient) KnownHosts() sdkssh.KnownHostsClient         { return m.kh }
func (m *mockSSHClient) AuthorizedKeys() sdkssh.AuthorizedKeysClient { return m.ak }
func (m *mockSSHClient) Session() sdkssh.SessionClient               { return nil }
func (m *mockSSHClient) Close() error                                { return nil }

type mockKeysClient struct {
	genResp    *sdkssh.Key
	genErr     error
	importResp *sdkssh.Key
	importErr  error
	getResp    *sdkssh.Key
	getErr     error
	listResp   []*sdkssh.Key
	listErr    error
	deleteErr  error
	exportResp *sdkssh.PublicKey
	exportErr  error
	signer     gossh.Signer
	signerErr  error
}

func (m *mockKeysClient) Generate(_ context.Context, _ sdkssh.GenerateRequest) (*sdkssh.Key, error) {
	return m.genResp, m.genErr
}
func (m *mockKeysClient) Import(_ context.Context, _ sdkssh.ImportRequest, _ secure.PassphraseProvider) (*sdkssh.Key, error) {
	return m.importResp, m.importErr
}
func (m *mockKeysClient) Get(_ context.Context, _ sdkssh.GetKeyRequest) (*sdkssh.Key, error) {
	return m.getResp, m.getErr
}
func (m *mockKeysClient) List(_ context.Context, _ sdkssh.ListKeysRequest) ([]*sdkssh.Key, error) {
	return m.listResp, m.listErr
}
func (m *mockKeysClient) Delete(_ context.Context, _ sdkssh.DeleteKeyRequest) error {
	return m.deleteErr
}
func (m *mockKeysClient) ExportPublic(_ context.Context, _ sdkssh.ExportRequest) (*sdkssh.PublicKey, error) {
	return m.exportResp, m.exportErr
}
func (m *mockKeysClient) Signer(_ context.Context, _ sdkssh.GetKeyRequest) (gossh.Signer, error) {
	return m.signer, m.signerErr
}

type mockKnownHostsClient struct {
	addErr   error
	listResp []*sdkssh.Pin
	listErr  error
	rmErr    error
}

func (m *mockKnownHostsClient) Add(_ context.Context, _ sdkssh.AddKnownHostRequest) error {
	return m.addErr
}
func (m *mockKnownHostsClient) List(_ context.Context, _ sdkssh.ListKnownHostsRequest) ([]*sdkssh.Pin, error) {
	return m.listResp, m.listErr
}
func (m *mockKnownHostsClient) Remove(_ context.Context, _ sdkssh.RemoveKnownHostRequest) error {
	return m.rmErr
}
func (m *mockKnownHostsClient) Verify(_ context.Context, _, _, _ string, _ gossh.PublicKey) error {
	return nil
}
func (m *mockKnownHostsClient) Callback(_ context.Context, _, _ string) gossh.HostKeyCallback {
	return nil
}

type mockAuthorizedKeysClient struct {
	addErr   error
	getResp  *sdkssh.AuthorizedEntry
	getErr   error
	listResp []*sdkssh.AuthorizedEntry
	listErr  error
	rmErr    error
	emitResp string
	emitErr  error
}

func (m *mockAuthorizedKeysClient) Add(_ context.Context, _ sdkssh.AddAuthorizedKeyRequest) error {
	return m.addErr
}
func (m *mockAuthorizedKeysClient) Get(_ context.Context, _, _, _ string) (*sdkssh.AuthorizedEntry, error) {
	return m.getResp, m.getErr
}
func (m *mockAuthorizedKeysClient) List(_ context.Context, _ sdkssh.ListAuthorizedKeysRequest) ([]*sdkssh.AuthorizedEntry, error) {
	return m.listResp, m.listErr
}
func (m *mockAuthorizedKeysClient) Remove(_ context.Context, _, _, _ string) error {
	return m.rmErr
}
func (m *mockAuthorizedKeysClient) Emit(_ context.Context, _ sdkssh.EmitRequest) (string, error) {
	return m.emitResp, m.emitErr
}
func (m *mockAuthorizedKeysClient) Verify(_ context.Context, _, _ string, _ gossh.PublicKey) (*sdkssh.AuthorizedEntry, error) {
	return nil, nil
}

// newMockSSHClient returns an empty, fully wired mock client.
func newMockSSHClient() *mockSSHClient {
	return &mockSSHClient{
		keys: &mockKeysClient{},
		kh:   &mockKnownHostsClient{},
		ak:   &mockAuthorizedKeysClient{},
	}
}

// newSSHTestServer mounts the SSH routes against the mock client.
func newSSHTestServer(t *testing.T, mc *mockSSHClient) *httptest.Server {
	t.Helper()
	h, err := NewSSHHandlers(mc, nil)
	require.NoError(t, err)
	r := chi.NewRouter()
	h.Register(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func base64Std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func sshTestSigner(t *testing.T) (gossh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(priv)
	require.NoError(t, err)
	line := string(gossh.MarshalAuthorizedKey(signer.PublicKey()))
	return signer, strings.TrimSpace(line)
}

// -----------------------------------------------------------------------------
// Constructor / error-type tests
// -----------------------------------------------------------------------------

func TestNewSSHHandlers(t *testing.T) {
	t.Run("nil client", func(t *testing.T) {
		_, err := NewSSHHandlers(nil, nil)
		require.Error(t, err)
		var nilErr *SSHNilError
		require.True(t, errors.As(err, &nilErr))
		assert.Equal(t, "client", nilErr.Field)
		assert.Contains(t, err.Error(), "client")
	})

	t.Run("nil logger defaults", func(t *testing.T) {
		h, err := NewSSHHandlers(newMockSSHClient(), nil)
		require.NoError(t, err)
		assert.NotNil(t, h.logger)
	})
}

func TestSSHBadBodyError(t *testing.T) {
	t.Run("with wrapped error", func(t *testing.T) {
		inner := errors.New("boom")
		e := &SSHBadBodyError{Err: inner}
		assert.Contains(t, e.Error(), "boom")
		assert.Equal(t, inner, e.Unwrap())
	})
	t.Run("nil error", func(t *testing.T) {
		e := &SSHBadBodyError{}
		assert.Equal(t, "rest/ssh: bad request body", e.Error())
		assert.Nil(t, e.Unwrap())
	})
}

// -----------------------------------------------------------------------------
// Keys
// -----------------------------------------------------------------------------

func TestSSHHandleGenerate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.keys.genResp = &sdkssh.Key{Scope: "user", Owner: "alice", Name: "k", Algorithm: "ed25519"}
		srv := newSSHTestServer(t, mc)

		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys", "application/json",
			strings.NewReader(`{"scope":"user","owner":"alice","name":"k","algorithm":"ed25519"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("bad body", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys", "application/json", strings.NewReader("{bad"))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("client error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.keys.genErr = errors.New("generate failed")
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys", "application/json", strings.NewReader(`{"name":"k"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

func TestSSHHandleImport(t *testing.T) {
	t.Run("success without passphrase", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.keys.importResp = &sdkssh.Key{Name: "imported"}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys/import", "application/json",
			strings.NewReader(`{"scope":"user","owner":"a","name":"imported","pem":"AAAA"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("bad body", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys/import", "application/json",
			strings.NewReader(`{"unknown_field":1}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("client error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.keys.importErr = errors.New("import failed")
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys/import", "application/json",
			strings.NewReader(`{"name":"imported","pem":"AAAA"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

func TestSSHHandleListKeys(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.keys.listResp = []*sdkssh.Key{{Name: "k1"}, {Name: "k2"}}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Get(srv.URL + "/xkms/v1/ssh/keys?scope=user&owner=alice")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var wire restKeyListWire
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&wire))
		assert.Len(t, wire.Items, 2)
	})

	t.Run("client error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.keys.listErr = errors.New("boom")
		srv := newSSHTestServer(t, mc)
		resp, err := http.Get(srv.URL + "/xkms/v1/ssh/keys")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

func TestSSHHandleGetKey(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.keys.getResp = &sdkssh.Key{Name: "k"}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Get(srv.URL + "/xkms/v1/ssh/keys/user/alice/k")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("not found maps to 404", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.keys.getErr = &pkgkeys.KeyNotFoundError{ID: "k"}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Get(srv.URL + "/xkms/v1/ssh/keys/user/alice/k")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
		var env sshErrorEnvelope
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
		assert.Equal(t, "key", env.Resource)
	})
}

func TestSSHHandleDeleteKey(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/xkms/v1/ssh/keys/user/alice/k", nil)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.keys.deleteErr = errors.New("boom")
		srv := newSSHTestServer(t, mc)
		req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/xkms/v1/ssh/keys/user/alice/k", nil)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

func TestSSHHandleExportPublic(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.keys.exportResp = &sdkssh.PublicKey{Algorithm: "ed25519", Line: "ssh-ed25519 AAAA"}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Get(srv.URL + "/xkms/v1/ssh/keys/user/alice/k/public")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.keys.exportErr = errors.New("boom")
		srv := newSSHTestServer(t, mc)
		resp, err := http.Get(srv.URL + "/xkms/v1/ssh/keys/user/alice/k/public")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

func TestSSHHandleSign(t *testing.T) {
	signer, _ := sshTestSigner(t)

	t.Run("success", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.keys.signer = signer
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys/user/alice/k/sign", "application/json",
			strings.NewReader(`{"digest":"`+base64Std("hello world digest!!")+`"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var out restSignResponseDTO
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		assert.NotEmpty(t, out.Format)
		assert.NotEmpty(t, out.Blob)
	})

	t.Run("bad body", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys/user/alice/k/sign", "application/json", strings.NewReader("{bad"))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("missing digest", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys/user/alice/k/sign", "application/json", strings.NewReader(`{}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("signer open error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.keys.signerErr = errors.New("no signer")
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys/user/alice/k/sign", "application/json",
			strings.NewReader(`{"digest":"`+base64Std("digest")+`"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// -----------------------------------------------------------------------------
// Known hosts
// -----------------------------------------------------------------------------

func TestSSHKnownHosts(t *testing.T) {
	t.Run("add success", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/known-hosts", "application/json",
			strings.NewReader(`{"scope":"user","owner":"a","host":"h","fingerprint":"SHA256:x"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("add bad body", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/known-hosts", "application/json", strings.NewReader("{bad"))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("add client error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.kh.addErr = &pkgknownhosts.DuplicateError{Scope: "user", Owner: "a", Host: "h"}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/known-hosts", "application/json",
			strings.NewReader(`{"host":"h"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		var env sshErrorEnvelope
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
		assert.Equal(t, "known_hosts", env.Resource)
	})

	t.Run("list success", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.kh.listResp = []*sdkssh.Pin{{Host: "h1"}}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Get(srv.URL + "/xkms/v1/ssh/known-hosts?scope=user&owner=a")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var wire restPinListWire
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&wire))
		assert.Len(t, wire.Items, 1)
	})

	t.Run("list error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.kh.listErr = errors.New("boom")
		srv := newSSHTestServer(t, mc)
		resp, err := http.Get(srv.URL + "/xkms/v1/ssh/known-hosts")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("remove success", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/xkms/v1/ssh/known-hosts/h?scope=user&owner=a", nil)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("remove error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.kh.rmErr = errors.New("boom")
		srv := newSSHTestServer(t, mc)
		req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/xkms/v1/ssh/known-hosts/h", nil)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

func TestSSHVerifyKnownHost(t *testing.T) {
	t.Run("bad body", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/known-hosts/h/verify", "application/json", strings.NewReader("{bad"))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("list error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.kh.listErr = errors.New("boom")
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/known-hosts/h/verify", "application/json",
			strings.NewReader(`{"scope":"user","owner":"a","fingerprint":"SHA256:x"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("pin not found", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.kh.listResp = []*sdkssh.Pin{{Host: "other", Fingerprint: "SHA256:y"}}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/known-hosts/h/verify", "application/json",
			strings.NewReader(`{"scope":"user","owner":"a","fingerprint":"SHA256:x"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("fingerprint mismatch", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.kh.listResp = []*sdkssh.Pin{{Host: "h", Fingerprint: "SHA256:expected"}}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/known-hosts/h/verify", "application/json",
			strings.NewReader(`{"scope":"user","owner":"a","fingerprint":"SHA256:received"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusConflict, resp.StatusCode)
		var env sshErrorEnvelope
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
		assert.Equal(t, "SHA256:expected", env.Expected)
		assert.Equal(t, "SHA256:received", env.Received)
	})

	t.Run("match", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.kh.listResp = []*sdkssh.Pin{{Host: "h", Fingerprint: "SHA256:match"}}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/known-hosts/h/verify", "application/json",
			strings.NewReader(`{"scope":"user","owner":"a","fingerprint":"SHA256:match"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})
}

// -----------------------------------------------------------------------------
// Authorized keys
// -----------------------------------------------------------------------------

func TestSSHAuthorizedKeys(t *testing.T) {
	t.Run("add success", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/authorized-keys", "application/json",
			strings.NewReader(`{"scope":"user","owner":"a","name":"n","line":"ssh-ed25519 AAAA"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("add bad body", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/authorized-keys", "application/json", strings.NewReader("{bad"))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("add client error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.ak.addErr = errors.New("boom")
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/authorized-keys", "application/json", strings.NewReader(`{"name":"n"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("list success", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.ak.listResp = []*sdkssh.AuthorizedEntry{{Name: "n"}}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Get(srv.URL + "/xkms/v1/ssh/authorized-keys?scope=user&owner=a")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var wire restAuthorizedListWire
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&wire))
		assert.Len(t, wire.Items, 1)
	})

	t.Run("list error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.ak.listErr = errors.New("boom")
		srv := newSSHTestServer(t, mc)
		resp, err := http.Get(srv.URL + "/xkms/v1/ssh/authorized-keys")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("get success", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.ak.getResp = &sdkssh.AuthorizedEntry{Name: "n"}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Get(srv.URL + "/xkms/v1/ssh/authorized-keys/user/alice/n")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("get not found", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.ak.getErr = &pkgauthorized.NotFoundError{Scope: "user", Owner: "a", Name: "n"}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Get(srv.URL + "/xkms/v1/ssh/authorized-keys/user/alice/n")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
		var env sshErrorEnvelope
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
		assert.Equal(t, "authorized_key", env.Resource)
	})

	t.Run("remove success", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/xkms/v1/ssh/authorized-keys/user/alice/n", nil)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("remove error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.ak.rmErr = errors.New("boom")
		srv := newSSHTestServer(t, mc)
		req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/xkms/v1/ssh/authorized-keys/user/alice/n", nil)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("emit success", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.ak.emitResp = "ssh-ed25519 AAAA comment"
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/authorized-keys/emit", "application/json",
			strings.NewReader(`{"scope":"user","owner":"a","name":"n"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var out restEmitResponseDTO
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		assert.Equal(t, "ssh-ed25519 AAAA comment", out.Line)
	})

	t.Run("emit bad body", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/authorized-keys/emit", "application/json", strings.NewReader("{bad"))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("emit error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.ak.emitErr = errors.New("boom")
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/authorized-keys/emit", "application/json", strings.NewReader(`{"name":"n"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

func TestSSHVerifyAuthorized(t *testing.T) {
	_, pubLine := sshTestSigner(t)
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(pubLine))
	require.NoError(t, err)
	fp := gossh.FingerprintSHA256(pub)

	t.Run("bad body", func(t *testing.T) {
		srv := newSSHTestServer(t, newMockSSHClient())
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/authorized-keys/verify", "application/json", strings.NewReader("{bad"))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("list error", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.ak.listErr = errors.New("boom")
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/authorized-keys/verify", "application/json",
			strings.NewReader(`{"scope":"user","owner":"a","fingerprint":"`+fp+`"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("match", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.ak.listResp = []*sdkssh.AuthorizedEntry{{Name: "n", Line: pubLine}}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/authorized-keys/verify", "application/json",
			strings.NewReader(`{"scope":"user","owner":"a","fingerprint":"`+fp+`"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("no match", func(t *testing.T) {
		mc := newMockSSHClient()
		mc.ak.listResp = []*sdkssh.AuthorizedEntry{{Name: "n", Line: "garbage"}}
		srv := newSSHTestServer(t, mc)
		resp, err := http.Post(srv.URL+"/xkms/v1/ssh/authorized-keys/verify", "application/json",
			strings.NewReader(`{"scope":"user","owner":"a","fingerprint":"`+fp+`"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
		var env sshErrorEnvelope
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
		assert.Equal(t, "authorized_key", env.Resource)
	})
}

// -----------------------------------------------------------------------------
// Helpers / unexported function coverage
// -----------------------------------------------------------------------------

func TestSSHErrorResourceMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"key", &pkgkeys.KeyNotFoundError{ID: "k"}, "key"},
		{"kh not found", &pkgknownhosts.NotFoundError{}, "known_hosts"},
		{"kh duplicate", &pkgknownhosts.DuplicateError{}, "known_hosts"},
		{"kh mismatch", &pkgknownhosts.MismatchError{}, "known_hosts"},
		{"auth not found", &pkgauthorized.NotFoundError{}, "authorized_key"},
		{"auth duplicate", &pkgauthorized.DuplicateError{}, "authorized_key"},
		{"unknown", errors.New("x"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sshErrorResource(tc.err))
		})
	}
}

func TestClassifySSHError(t *testing.T) {
	assert.Equal(t, http.StatusBadRequest, classifySSHError(&SSHBadBodyError{Err: errors.New("x")}))
	assert.Equal(t, http.StatusBadRequest, classifySSHError(&SSHNilError{Field: "client"}))
	assert.Equal(t, http.StatusNotFound, classifySSHError(&pkgkeys.KeyNotFoundError{ID: "k"}))
}

func TestWriteSSHErrorWithMismatch(t *testing.T) {
	w := httptest.NewRecorder()
	writeSSHError(w, &pkgknownhosts.MismatchError{Host: "h", Expected: "e", Received: "r"})
	require.Equal(t, http.StatusConflict, w.Code)
	var env sshErrorEnvelope
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	assert.Equal(t, "h", env.Host)
	assert.Equal(t, "e", env.Expected)
	assert.Equal(t, "r", env.Received)
}
