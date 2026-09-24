// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// This file pins the REST client's "malformed server response" error path:
// a 2xx response whose body is not valid JSON for the expected shape must
// surface a typed *ProtocolError, never a panic or a zero-value success.
package ssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// malformedJSONServer answers every request with a 200 status and a body
// that is not valid JSON for any of this package's response shapes.
func malformedJSONServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not valid json"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRESTKeys_Generate_MalformedResponseIsProtocolError(t *testing.T) {
	srv := malformedJSONServer(t)
	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Keys().Generate(context.Background(), sdkssh.GenerateRequest{
		Scope: "user", Owner: "a", Name: "n", Algorithm: "ed25519",
	})
	var pe *sdkssh.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
	}
}

func TestRESTKeys_ExportPublic_MalformedResponseIsProtocolError(t *testing.T) {
	srv := malformedJSONServer(t)
	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Keys().ExportPublic(context.Background(), sdkssh.ExportRequest{Scope: "user", Owner: "a", Name: "n"})
	var pe *sdkssh.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
	}
}

func TestRESTAuthorizedKeys_Get_MalformedResponseIsProtocolError(t *testing.T) {
	srv := malformedJSONServer(t)
	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.AuthorizedKeys().Get(context.Background(), "user", "a", "n")
	var pe *sdkssh.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
	}
}

func TestRESTAuthorizedKeys_List_MalformedResponseIsProtocolError(t *testing.T) {
	srv := malformedJSONServer(t)
	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.AuthorizedKeys().List(context.Background(), sdkssh.ListAuthorizedKeysRequest{Scope: "user", Owner: "a"})
	var pe *sdkssh.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
	}
}

func TestRESTKnownHosts_List_MalformedResponseIsProtocolError(t *testing.T) {
	srv := malformedJSONServer(t)
	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.KnownHosts().List(context.Background(), sdkssh.ListKnownHostsRequest{Scope: "user", Owner: "a"})
	var pe *sdkssh.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
	}
}

func TestRESTAuthorizedKeys_Emit_MalformedResponseIsProtocolError(t *testing.T) {
	srv := malformedJSONServer(t)
	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.AuthorizedKeys().Emit(context.Background(), sdkssh.EmitRequest{PublicKey: "ssh-ed25519 AAAA"})
	var pe *sdkssh.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
	}
}

func TestRESTAuthorizedKeys_Verify_MalformedResponseIsProtocolError(t *testing.T) {
	srv := malformedJSONServer(t)
	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}

	_, err = client.AuthorizedKeys().Verify(context.Background(), "user", "a", signer.PublicKey())
	var pe *sdkssh.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
	}
}

// TestRESTKeys_Signer_MalformedPublicKeyLineIsProtocolError covers the
// parseExportedPublicKey failure path: ExportPublic returns a syntactically
// valid response, but a Line the server did not encode as an
// authorized_keys entry must surface *ProtocolError rather than a nil or
// corrupt gossh.PublicKey inside the returned signer.
func TestRESTKeys_Signer_MalformedPublicKeyLineIsProtocolError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/xkms/v1/ssh/keys/user/a/n/public", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"algorithm":"ssh-ed25519","line":"not an authorized_keys line"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{Scope: "user", Owner: "a", Name: "n"})
	var pe *sdkssh.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
	}
}

// TestRESTSigner_Sign_MalformedResponseIsProtocolError covers the
// remote-signer proxy's Sign method: ExportPublic must succeed (its
// response feeds the cached public key) but the /sign endpoint returning a
// malformed body must surface *ProtocolError rather than a bad signature.
func TestRESTSigner_Sign_MalformedResponseIsProtocolError(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	line := authorizedKeyLine(signer.PublicKey())

	mux := http.NewServeMux()
	mux.HandleFunc("/xkms/v1/ssh/keys/user/a/n/public", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"algorithm":"` + signer.PublicKey().Type() + `","line":"` + line + `"}`))
	})
	mux.HandleFunc("/xkms/v1/ssh/keys/user/a/n/sign", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not valid json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer func() { _ = client.Close() }()

	remoteSigner, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{Scope: "user", Owner: "a", Name: "n"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	_, err = remoteSigner.Sign(nil, []byte("digest"))
	var pe *sdkssh.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
	}
}
