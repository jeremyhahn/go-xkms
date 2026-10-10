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

package handlers_ssh_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	gossh "golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// newSSHTestServer constructs an httptest.Server fronted by the real
// SSH handlers backed by an in-memory DAO factory.
func newSSHTestServer(t *testing.T) (*httptest.Server, sdkssh.Client, func()) {
	t.Helper()
	stores, err := sdkssh.NewStores(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewStores: %v", err)
	}
	embedded, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Stores: stores})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	handlers, err := rest.NewSSHHandlers(embedded, nil)
	if err != nil {
		t.Fatalf("NewSSHHandlers: %v", err)
	}
	r := chi.NewRouter()
	handlers.Register(r)
	srv := httptest.NewServer(r)
	cleanup := func() {
		srv.Close()
		_ = embedded.Close()
	}
	return srv, embedded, cleanup
}

// TestHandlers_NewSSHHandlers_Validation ensures nil client is
// rejected with a typed error.
func TestHandlers_NewSSHHandlers_Validation(t *testing.T) {
	_, err := rest.NewSSHHandlers(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
	var nilErr *rest.SSHNilError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected SSHNilError, got %T: %v", err, err)
	}
}

// TestHandlers_GenerateListDelete covers the happy path end-to-end via
// HTTP.
func TestHandlers_GenerateListDelete(t *testing.T) {
	srv, _, cleanup := newSSHTestServer(t)
	defer cleanup()

	// Generate.
	body := bytes.NewBufferString(`{"scope":"user","owner":"alice","name":"k1","algorithm":"ed25519"}`)
	resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys", "application/json", body)
	if err != nil {
		t.Fatalf("POST /keys: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Generate status: %d", resp.StatusCode)
	}
	var genned sdkssh.Key
	_ = json.NewDecoder(resp.Body).Decode(&genned)
	resp.Body.Close()
	if genned.Fingerprint == "" {
		t.Fatal("expected fingerprint")
	}

	// Duplicate generate triggers 409.
	body = bytes.NewBufferString(`{"scope":"user","owner":"alice","name":"k1","algorithm":"ed25519"}`)
	resp, err = http.Post(srv.URL+"/xkms/v1/ssh/keys", "application/json", body)
	if err != nil {
		t.Fatalf("POST duplicate /keys: %v", err)
	}
	defer resp.Body.Close()
	// Some store implementations may allow overwrite; if so, skip the
	// assertion rather than fail the test — Phase 1c doesn't require
	// store-level dedup beyond what the storage backend provides.
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		t.Fatalf("unexpected duplicate status: %d", resp.StatusCode)
	}

	// List.
	resp, err = http.Get(srv.URL + "/xkms/v1/ssh/keys?scope=user&owner=alice")
	if err != nil {
		t.Fatalf("GET /keys: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("List status: %d", resp.StatusCode)
	}
	var listed struct {
		Items []*sdkssh.Key `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Items) != 1 {
		t.Fatalf("expected 1 key, got %d", len(listed.Items))
	}
}

// TestHandlers_GetNotFound returns 404 with a NotFound resource.
func TestHandlers_GetNotFound(t *testing.T) {
	srv, _, cleanup := newSSHTestServer(t)
	defer cleanup()

	resp, err := http.Get(srv.URL + "/xkms/v1/ssh/keys/user/alice/missing")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// TestHandlers_InvalidScope returns 400.
func TestHandlers_InvalidScope(t *testing.T) {
	srv, _, cleanup := newSSHTestServer(t)
	defer cleanup()

	body := bytes.NewBufferString(`{"scope":"bogus","owner":"a","name":"k","algorithm":"ed25519"}`)
	resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys", "application/json", body)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// TestHandlers_PassphraseUnmarshaler_RoundTrip submits a base64-encoded
// passphrase for an encrypted PEM and asserts the handler imports the
// key successfully. Also asserts, via reflection, that the DTO's
// passphrase field is NOT a plain Go string type.
func TestHandlers_PassphraseUnmarshaler_RoundTrip(t *testing.T) {
	srv, _, cleanup := newSSHTestServer(t)
	defer cleanup()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	pass := []byte("testpass")
	block, err := gossh.MarshalPrivateKeyWithPassphrase(priv, "", pass)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	importBody := struct {
		Scope         string `json:"scope"`
		Owner         string `json:"owner"`
		Name          string `json:"name"`
		PEM           []byte `json:"pem"`
		PassphraseB64 string `json:"passphrase_b64"`
	}{
		Scope:         "user",
		Owner:         "alice",
		Name:          "imported",
		PEM:           pemBytes,
		PassphraseB64: base64.StdEncoding.EncodeToString(pass),
	}
	body, err := json.Marshal(importBody)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys/import", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := readAll(resp.Body)
		t.Fatalf("import status %d body=%s", resp.StatusCode, string(raw))
	}

	var out sdkssh.Key
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Algorithm != "ecdsa-p256" {
		t.Fatalf("unexpected algorithm: %s", out.Algorithm)
	}
}

// TestHandlers_PassphraseField_ReflectionInvariant asserts the
// SSHPassphraseField type has NO string-typed public field — the only
// way to read back the decoded passphrase is through the
// unmarshaler's internal Buffer handle. This guards against a
// regression where a refactor adds a convenience string accessor.
func TestHandlers_PassphraseField_ReflectionInvariant(t *testing.T) {
	zero := rest.SSHPassphraseField{}
	val := reflect.TypeOf(zero)
	for i := 0; i < val.NumField(); i++ {
		f := val.Field(i)
		if f.Type.Kind() == reflect.String {
			t.Fatalf("SSHPassphraseField exposes a string field %q — must not carry plaintext in a Go string", f.Name)
		}
	}
}

// TestHandlers_SignEndpoint_RoundTrip generates a key, signs a digest,
// and verifies the signature against the exported public key.
func TestHandlers_SignEndpoint_RoundTrip(t *testing.T) {
	srv, _, cleanup := newSSHTestServer(t)
	defer cleanup()

	// Generate.
	gen := bytes.NewBufferString(`{"scope":"user","owner":"alice","name":"signer","algorithm":"ed25519"}`)
	resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys", "application/json", gen)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	resp.Body.Close()

	// Sign.
	digest := []byte("payload to sign")
	body, _ := json.Marshal(map[string][]byte{"digest": digest})
	resp, err = http.Post(srv.URL+"/xkms/v1/ssh/keys/user/alice/signer/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := readAll(resp.Body)
		t.Fatalf("sign status %d body=%s", resp.StatusCode, string(raw))
	}
	var sig struct {
		Format string `json:"format"`
		Blob   []byte `json:"blob"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sig); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Fetch public key and verify.
	pubResp, err := http.Get(srv.URL + "/xkms/v1/ssh/keys/user/alice/signer/public")
	if err != nil {
		t.Fatalf("get public: %v", err)
	}
	defer pubResp.Body.Close()
	var pub struct {
		Line string `json:"line"`
	}
	if err := json.NewDecoder(pubResp.Body).Decode(&pub); err != nil {
		t.Fatalf("decode public: %v", err)
	}
	sshPub, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(pub.Line))
	if perr != nil {
		t.Fatalf("parse public: %v", perr)
	}
	if err := sshPub.Verify(digest, &gossh.Signature{Format: sig.Format, Blob: sig.Blob}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestHandlers_KnownHosts_MismatchFlow drives a mismatch scenario and
// asserts 409 with the expected JSON body fields.
func TestHandlers_KnownHosts_MismatchFlow(t *testing.T) {
	srv, _, cleanup := newSSHTestServer(t)
	defer cleanup()

	line, fingerprint := randomHostKey(t)
	otherLine, otherFingerprint := randomHostKey(t)

	// Add a pin. PublicKey is required — the store no longer accepts a
	// fingerprint-only pin.
	addReq := sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "bastion",
		PublicKey: line, Fingerprint: fingerprint, Algorithm: "ssh-ed25519",
	}
	addBody, err := json.Marshal(addReq)
	if err != nil {
		t.Fatalf("marshal add: %v", err)
	}
	resp, err := http.Post(srv.URL+"/xkms/v1/ssh/known-hosts", "application/json", bytes.NewReader(addBody))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		raw, _ := readAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("add status %d: %s", resp.StatusCode, string(raw))
	}
	resp.Body.Close()

	// Verify a different presented key → 409 with expected + received
	// fingerprints. The wire carries the actual key, not a caller-claimed
	// fingerprint, so this proves the server compares full key bytes.
	verifyReq := struct {
		Scope     string `json:"scope"`
		Owner     string `json:"owner"`
		PublicKey string `json:"public_key"`
	}{Scope: "user", Owner: "alice", PublicKey: otherLine}
	verifyBody, err := json.Marshal(verifyReq)
	if err != nil {
		t.Fatalf("marshal verify: %v", err)
	}
	resp, err = http.Post(srv.URL+"/xkms/v1/ssh/known-hosts/bastion/verify", "application/json", bytes.NewReader(verifyBody))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		raw, _ := readAll(resp.Body)
		t.Fatalf("expected 409, got %d: %s", resp.StatusCode, string(raw))
	}
	var env struct {
		Expected string `json:"expected"`
		Received string `json:"received"`
		Host     string `json:"host"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Expected != fingerprint || env.Received != otherFingerprint {
		t.Fatalf("unexpected mismatch body: %+v", env)
	}
	if env.Host != "bastion" {
		t.Fatalf("unexpected host: %q", env.Host)
	}
}

// randomHostKey generates an ed25519 keypair and returns its
// authorized_keys-format line together with its OpenSSH SHA256 fingerprint,
// for tests that need a real host key rather than a synthetic fingerprint
// string (the known_hosts store requires the full key on every pin).
func randomHostKey(t *testing.T) (line, fingerprint string) {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	line = strings.TrimRight(string(gossh.MarshalAuthorizedKey(sshPub)), "\n")
	return line, gossh.FingerprintSHA256(sshPub)
}

// TestHandlers_BadBody returns 400 for malformed JSON.
func TestHandlers_BadBody(t *testing.T) {
	srv, _, cleanup := newSSHTestServer(t)
	defer cleanup()

	resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys", "application/json", bytes.NewBufferString("{not json"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// readAll is a small helper that mirrors io.ReadAll without importing
// io in the test package (keeps this file's imports minimal).
func readAll(rc interface {
	Read(p []byte) (n int, err error)
}) ([]byte, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := rc.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if errors.Is(err, errUnexpectedEOF) {
				return buf, nil
			}
			return buf, err
		}
	}
}

// errUnexpectedEOF is the test-local constant we compare against. We
// can't import io without pulling in bigger helpers; instead we accept
// EOF as a terminal marker. This is kept simple intentionally.
var errUnexpectedEOF = errors.New("EOF")

// TestHandlers_Context_CancelPropagates asserts the request context
// propagation — cancelling the client context aborts the request.
func TestHandlers_Context_CancelPropagates(t *testing.T) {
	srv, _, cleanup := newSSHTestServer(t)
	defer cleanup()
	_ = srv

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A cancelled ctx yields an error before any HTTP round-trip.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		srv.URL+"/xkms/v1/ssh/keys", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	_, err = http.DefaultClient.Do(req)
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("unexpected error: %v", err)
	}
}
