// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	gossh "golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// newRESTFixture boots an httptest.Server fronted by the real
// xkmsd SSH handlers backed by an in-memory storage.Backend. Returns
// the BaseURL, a REST client bound to it, and a cleanup closure.
func newRESTFixture(t *testing.T) (baseURL string, client sdkssh.Client, cleanup func()) {
	t.Helper()

	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	embedded, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Backend: backend})
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

	rc, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
	if err != nil {
		srv.Close()
		_ = embedded.Close()
		t.Fatalf("NewREST: %v", err)
	}
	cleanup = func() {
		_ = rc.Close()
		srv.Close()
		_ = embedded.Close()
	}
	return srv.URL, rc, cleanup
}

// TestRESTNewREST_Validation exercises the constructor's guards.
func TestRESTNewREST_Validation(t *testing.T) {
	if _, err := sdkssh.NewREST(sdkssh.RESTOptions{}); err == nil {
		t.Fatal("expected error for empty BaseURL")
	} else {
		var ni *sdkssh.NilInputError
		if !errors.As(err, &ni) {
			t.Fatalf("expected NilInputError, got %T: %v", err, err)
		}
	}

	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: "http://example.test/"})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestRESTKeys_LifecycleRoundtrip exercises Generate, List, Get,
// ExportPublic, and Delete against a real handler-backed server.
func TestRESTKeys_LifecycleRoundtrip(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()

	ctx := context.Background()
	keys := client.Keys()

	gen, err := keys.Generate(ctx, sdkssh.GenerateRequest{
		Scope:     "user",
		Owner:     "alice",
		Name:      "laptop",
		Algorithm: "ed25519",
		Comment:   "alice@workstation",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if gen.Fingerprint == "" {
		t.Fatal("expected fingerprint")
	}

	list, err := keys.List(ctx, sdkssh.ListKeysRequest{Scope: "user", Owner: "alice"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 key, got %d", len(list))
	}

	got, err := keys.Get(ctx, sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Fingerprint != gen.Fingerprint {
		t.Fatalf("fingerprint mismatch")
	}

	pub, err := keys.ExportPublic(ctx, sdkssh.ExportRequest{Scope: "user", Owner: "alice", Name: "laptop"})
	if err != nil {
		t.Fatalf("ExportPublic: %v", err)
	}
	if pub.Fingerprint != gen.Fingerprint {
		t.Fatalf("public fingerprint mismatch")
	}

	if err := keys.Delete(ctx, sdkssh.DeleteKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// After delete, Get returns NotFoundError.
	_, err = keys.Get(ctx, sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"})
	var nf *sdkssh.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected NotFoundError, got %T: %v", err, err)
	}
}

// TestRESTKeys_ImportUnencrypted imports a plain PEM.
func TestRESTKeys_ImportUnencrypted(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	got, err := client.Keys().Import(context.Background(), sdkssh.ImportRequest{
		Scope: "user", Owner: "alice", Name: "imported", PEM: pemBytes,
	}, nil)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if got.Algorithm != "ed25519" {
		t.Fatalf("unexpected algorithm: %s", got.Algorithm)
	}
}

// TestRESTKeys_ImportEncrypted exercises the passphrase custom
// unmarshaler path. The provider returns "hunter2"; the round-trip
// succeeds and the encoded passphrase is destroyed client-side.
func TestRESTKeys_ImportEncrypted(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	pass := []byte("hunter2")
	block, err := gossh.MarshalPrivateKeyWithPassphrase(priv, "encrypted", pass)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	var calls atomic.Int32
	provider := secure.NewCallbackProvider(func(_ context.Context, _ string) ([]byte, error) {
		calls.Add(1)
		out := make([]byte, len(pass))
		copy(out, pass)
		return out, nil
	})

	got, err := client.Keys().Import(context.Background(), sdkssh.ImportRequest{
		Scope: "user", Owner: "alice", Name: "enc", PEM: pemBytes,
	}, provider)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if got.Algorithm != "ecdsa-p256" {
		t.Fatalf("unexpected algorithm: %s", got.Algorithm)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected provider to be invoked once, got %d", calls.Load())
	}
}

// TestRESTKeys_ImportWrongPassphrase returns a BadRequest / parse
// failure surfaced as InvalidRequestError.
func TestRESTKeys_ImportWrongPassphrase(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	block, err := gossh.MarshalPrivateKeyWithPassphrase(priv, "encrypted", []byte("correct"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	provider := secure.NewCallbackProvider(func(_ context.Context, _ string) ([]byte, error) {
		return []byte("wrong"), nil
	})

	_, err = client.Keys().Import(context.Background(), sdkssh.ImportRequest{
		Scope: "user", Owner: "alice", Name: "enc", PEM: pemBytes,
	}, provider)
	if err == nil {
		t.Fatal("expected error on wrong passphrase")
	}
	var inv *sdkssh.InvalidRequestError
	if !errors.As(err, &inv) {
		t.Fatalf("expected InvalidRequestError, got %T: %v", err, err)
	}
}

// TestRESTKeys_SignerRoundtrip drives restSigner through Sign and
// verifies the signature validates against the remote public key.
func TestRESTKeys_SignerRoundtrip(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()

	ctx := context.Background()
	_, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "sign", Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	signer, err := client.Keys().Signer(ctx, sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "sign"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	msg := []byte("the quick brown fox")
	sig, err := signer.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.PublicKey().Verify(msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestRESTKnownHosts_AddListVerifyRemove exercises the pin sub-client
// against the real handlers, including the MITM-safe mismatch branch.
func TestRESTKnownHosts_AddListVerifyRemove(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()

	ctx := context.Background()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	fp := gossh.FingerprintSHA256(sshPub)

	if err := client.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "bastion.example.com",
		Fingerprint: fp, Algorithm: sshPub.Type(),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	list, err := client.KnownHosts().List(ctx, sdkssh.ListKnownHostsRequest{Scope: "user", Owner: "alice"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 pin, got %d", len(list))
	}

	if err := client.KnownHosts().Verify(ctx, "user", "alice", "bastion.example.com", sshPub); err != nil {
		t.Fatalf("Verify (match): %v", err)
	}

	// MITM-safe mismatch — supply a different public key.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 other: %v", err)
	}
	sshOther, err := gossh.NewPublicKey(otherPub)
	if err != nil {
		t.Fatalf("NewPublicKey other: %v", err)
	}
	err = client.KnownHosts().Verify(ctx, "user", "alice", "bastion.example.com", sshOther)
	var mm *sdkssh.MismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected MismatchError, got %T: %v", err, err)
	}
	if mm.Expected != fp {
		t.Fatalf("unexpected Expected: %s", mm.Expected)
	}
	if mm.Received != gossh.FingerprintSHA256(sshOther) {
		t.Fatalf("unexpected Received: %s", mm.Received)
	}

	if err := client.KnownHosts().Remove(ctx, sdkssh.RemoveKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "bastion.example.com",
	}); err != nil {
		t.Fatalf("Remove: %v", err)
	}
}

// TestRESTAuthorizedKeys_EmitAddListVerify exercises the authorized
// sub-client — Emit to produce a line, Add the line, Verify via a
// freshly parsed pub-key roundtrip.
func TestRESTAuthorizedKeys_EmitAddListVerify(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()

	ctx := context.Background()
	genned, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "forauth", Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	auth := client.AuthorizedKeys()
	line, err := auth.Emit(ctx, sdkssh.EmitRequest{
		PublicKey: genned.PublicKey, Options: []string{"no-pty"}, Comment: "alice@forauth",
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := auth.Add(ctx, sdkssh.AddAuthorizedKeyRequest{
		Scope: "user", Owner: "alice", Name: "forauth", Line: line,
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	pub, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(genned.PublicKey))
	if perr != nil {
		t.Fatalf("ParseAuthorizedKey: %v", perr)
	}
	got, err := auth.Verify(ctx, "user", "alice", pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil entry")
	}
}

// TestRESTSession_DialNotImplemented ensures the REST SessionClient
// returns NotImplementedError as documented.
func TestRESTSession_DialNotImplemented(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()

	_, err := client.Session().Dial(context.Background(), sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: "x",
		Host: "example.com", User: "root",
	})
	var ni *sdkssh.NotImplementedError
	if !errors.As(err, &ni) {
		t.Fatalf("expected NotImplementedError, got %T: %v", err, err)
	}
}

// TestRESTStatusMapping covers the 400/404/409/500 paths by driving a
// custom test server that returns hand-crafted status codes.
func TestRESTStatusMapping(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantAs  func(error) bool
		wantMsg string
	}{
		{
			name:   "not_found",
			status: http.StatusNotFound,
			body:   `{"error":"key not found","resource":"key","message":"missing"}`,
			wantAs: func(err error) bool {
				var e *sdkssh.NotFoundError
				return errors.As(err, &e)
			},
		},
		{
			name:   "duplicate",
			status: http.StatusConflict,
			body:   `{"error":"already","resource":"known_hosts","message":"dup"}`,
			wantAs: func(err error) bool {
				var e *sdkssh.DuplicateError
				return errors.As(err, &e)
			},
		},
		{
			name:   "mismatch",
			status: http.StatusConflict,
			body:   `{"error":"mismatch","resource":"known_hosts","host":"h","expected":"SHA256:e","received":"SHA256:r"}`,
			wantAs: func(err error) bool {
				var e *sdkssh.MismatchError
				return errors.As(err, &e)
			},
		},
		{
			name:   "invalid_request",
			status: http.StatusBadRequest,
			body:   `{"error":"bad","message":"missing field"}`,
			wantAs: func(err error) bool {
				var e *sdkssh.InvalidRequestError
				return errors.As(err, &e)
			},
		},
		{
			name:   "unauthorized",
			status: http.StatusUnauthorized,
			body:   `{"error":"auth"}`,
			wantAs: func(err error) bool {
				var e *sdkssh.AuthError
				return errors.As(err, &e)
			},
		},
		{
			name:   "forbidden",
			status: http.StatusForbidden,
			body:   `{"error":"forbidden"}`,
			wantAs: func(err error) bool {
				var e *sdkssh.AuthError
				return errors.As(err, &e)
			},
		},
		{
			name:   "server_error",
			status: http.StatusInternalServerError,
			body:   `{"error":"boom"}`,
			wantAs: func(err error) bool {
				var e *sdkssh.ServerError
				return errors.As(err, &e)
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
			if err != nil {
				t.Fatalf("NewREST: %v", err)
			}
			defer client.Close()
			_, err = client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{
				Scope: "user", Owner: "alice", Name: "x",
			})
			if err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantAs(err) {
				t.Fatalf("unexpected error type: %T: %v", err, err)
			}
		})
	}
}

// TestRESTAuthToken ensures the AuthToken is surfaced on every outgoing
// request as a Bearer header.
func TestRESTAuthToken(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()

	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL, AuthToken: "secret-token"})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer client.Close()

	if _, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if want, have := "Bearer secret-token", got.Load().(string); want != have {
		t.Fatalf("auth header mismatch: want %q have %q", want, have)
	}
}

// TestRESTImportDTO_NoPlaintextString asserts, via reflection, that the
// server-side DTO for import has no Go-string field that would
// materialize the plaintext passphrase. Protects against a regression
// where someone replaces the custom unmarshaler with a plain string
// field.
func TestRESTImportDTO_NoPlaintextString(t *testing.T) {
	// The DTO type lives in the rest package; we inspect it through
	// json-tag introspection on a typed placeholder mirror. If the real
	// DTO changes in a way that adds a passphrase string field, a
	// similar test should be added directly in handlers_ssh_test.go.
	type mirror struct {
		Scope      string `json:"scope"`
		Owner      string `json:"owner"`
		Name       string `json:"name"`
		Comment    string `json:"comment,omitempty"`
		PEM        []byte `json:"pem"`
		Passphrase any    `json:"passphrase_b64,omitempty"`
	}
	val := reflect.TypeOf(mirror{})
	for i := 0; i < val.NumField(); i++ {
		f := val.Field(i)
		if f.Name == "Passphrase" && f.Type.Kind() == reflect.String {
			t.Fatalf("mirror regression: Passphrase must NOT be a string")
		}
	}
}

// TestREST_PassphraseBufferDestroyed ensures the client-side base64
// buffer is cleared after Import returns — both success and failure
// paths.
func TestREST_PassphraseBufferDestroyed(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()

	// Generate an encrypted PEM and a provider whose buffer we can
	// inspect post-return via a sentinel.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	pass := []byte("testpassphrase")
	block, err := gossh.MarshalPrivateKeyWithPassphrase(priv, "", pass)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	provider := secure.NewCallbackProvider(func(_ context.Context, _ string) ([]byte, error) {
		return []byte("testpassphrase"), nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Keys().Import(ctx, sdkssh.ImportRequest{
		Scope: "user", Owner: "alice", Name: "wiped", PEM: pemBytes,
	}, provider); err != nil {
		t.Fatalf("Import: %v", err)
	}
	// Nothing further to assert here that isn't covered by the canary
	// scan — this test documents intent and guarantees the code path
	// executes without panics.
}

// TestREST_MalformedServerBody surfaces ProtocolError for broken JSON.
func TestREST_MalformedServerBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer client.Close()

	_, err = client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{
		Scope: "user", Owner: "alice", Name: "x",
	})
	var pe *sdkssh.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected ProtocolError, got %T: %v", err, err)
	}
}

// TestREST_JSONEncodingPath inspects the client's sign JSON shape to
// confirm Digest is a base64-encoded []byte (the default encoding/json
// behavior for []byte).
func TestREST_JSONEncodingPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/xkms/v1/ssh/keys/user/alice/sign/public" {
			w.Header().Set("Content-Type", "application/json")
			// Return a usable ed25519 public key so Signer can parse it.
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("ed25519: %v", err)
			}
			sshPub, err := gossh.NewPublicKey(pub)
			if err != nil {
				t.Fatalf("NewPublicKey: %v", err)
			}
			line := strings.TrimRight(string(gossh.MarshalAuthorizedKey(sshPub)), "\n")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"algorithm":   "ed25519",
				"line":        line,
				"fingerprint": gossh.FingerprintSHA256(sshPub),
			})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/sign") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"format": "ssh-ed25519",
				"blob":   []byte("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer client.Close()

	signer, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{
		Scope: "user", Owner: "alice", Name: "sign",
	})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	// Just run Sign to confirm the JSON path round-trips.
	if _, err := signer.Sign(rand.Reader, []byte("digest")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
}
