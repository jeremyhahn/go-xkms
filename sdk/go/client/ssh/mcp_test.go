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

package ssh_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// ----------------------------------------------------------------------------
// Fake MCP (JSON-RPC 2.0 over newline-delimited TCP) server.
// ----------------------------------------------------------------------------

// mcpCall is one recorded request as it arrived on the wire.
type mcpCall struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      int64           `json:"id"`
}

// mcpHandler produces the JSON-RPC result for a method. Returning a non-nil
// rpcErr makes the server answer with an "error" member instead.
type mcpHandler func(params json.RawMessage) (result interface{}, code int, message string)

type fakeMCPServer struct {
	t        *testing.T
	ln       net.Listener
	handlers map[string]mcpHandler

	// rawResponse, when set for a method, is written verbatim instead of a
	// well-formed envelope — used to exercise hostile/broken servers.
	rawResponse map[string]string

	// closeOn names a method that makes the server hang up without replying.
	closeOn string

	mu    sync.Mutex
	calls []mcpCall
	wg    sync.WaitGroup
}

func newFakeMCPServer(t *testing.T) *fakeMCPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeMCPServer{
		t:           t,
		ln:          ln,
		handlers:    map[string]mcpHandler{},
		rawResponse: map[string]string{},
	}
	// Health always succeeds unless a test overrides it.
	s.handlers["health"] = func(json.RawMessage) (interface{}, int, string) {
		return map[string]string{"status": "ok"}, 0, ""
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serve(conn)
			}()
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *fakeMCPServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		var call mcpCall
		if err := json.Unmarshal(scanner.Bytes(), &call); err != nil {
			return
		}
		s.mu.Lock()
		s.calls = append(s.calls, call)
		closeOn := s.closeOn
		raw, hasRaw := s.rawResponse[call.Method]
		handler, hasHandler := s.handlers[call.Method]
		s.mu.Unlock()

		if closeOn != "" && call.Method == closeOn {
			return // hang up mid-conversation
		}
		if hasRaw {
			_, _ = conn.Write([]byte(raw + "\n"))
			continue
		}
		if !hasHandler {
			s.writeError(conn, call.ID, -32601, "method not found: "+call.Method)
			continue
		}
		result, code, message := handler(call.Params)
		if code != 0 {
			s.writeError(conn, call.ID, code, message)
			continue
		}
		body, err := json.Marshal(result)
		if err != nil {
			s.writeError(conn, call.ID, -32603, err.Error())
			continue
		}
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      call.ID,
			"result":  json.RawMessage(body),
		}
		line, _ := json.Marshal(resp)
		_, _ = conn.Write(append(line, '\n'))
	}
}

func (s *fakeMCPServer) writeError(conn net.Conn, id int64, code int, message string) {
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]interface{}{"code": code, "message": message},
	}
	line, _ := json.Marshal(resp)
	_, _ = conn.Write(append(line, '\n'))
}

func (s *fakeMCPServer) addr() string { return s.ln.Addr().String() }

func (s *fakeMCPServer) handle(method string, fn mcpHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[method] = fn
}

func (s *fakeMCPServer) ok(method string, result interface{}) {
	s.handle(method, func(json.RawMessage) (interface{}, int, string) { return result, 0, "" })
}

func (s *fakeMCPServer) fail(method string, code int, message string) {
	s.handle(method, func(json.RawMessage) (interface{}, int, string) { return nil, code, message })
}

// lastCall returns the most recent recorded call for method.
func (s *fakeMCPServer) lastCall(method string) *mcpCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.calls) - 1; i >= 0; i-- {
		if s.calls[i].Method == method {
			c := s.calls[i]
			return &c
		}
	}
	return nil
}

func (s *fakeMCPServer) allCalls() []mcpCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]mcpCall, len(s.calls))
	copy(out, s.calls)
	return out
}

// newMCPFixture returns a connected SDK MCP client for srv.
func newMCPFixture(t *testing.T, srv *fakeMCPServer) sdkssh.Client {
	t.Helper()
	client, err := sdkssh.NewMCP(sdkssh.MCPOptions{Addr: srv.addr()})
	if err != nil {
		t.Fatalf("NewMCP: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// paramsOf decodes the recorded params of the last call to method.
func paramsOf(t *testing.T, srv *fakeMCPServer, method string) map[string]interface{} {
	t.Helper()
	call := srv.lastCall(method)
	if call == nil {
		t.Fatalf("server never received %s (saw %v)", method, methodNames(srv.allCalls()))
	}
	var out map[string]interface{}
	if err := json.Unmarshal(call.Params, &out); err != nil {
		t.Fatalf("decode params of %s: %v", method, err)
	}
	return out
}

func methodNames(calls []mcpCall) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.Method)
	}
	return out
}

// ----------------------------------------------------------------------------
// Constructor / connection lifecycle.
// ----------------------------------------------------------------------------

func TestNewMCP_MissingAddr(t *testing.T) {
	_, err := sdkssh.NewMCP(sdkssh.MCPOptions{})
	var nilErr *sdkssh.NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected *NilInputError, got %T %v", err, err)
	}
	if nilErr.Field != "Addr" {
		t.Errorf("Field = %q", nilErr.Field)
	}
}

func TestNewMCP_DialFailure(t *testing.T) {
	// Bind and immediately close to get an address nothing is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if cerr := ln.Close(); cerr != nil {
		t.Fatalf("close: %v", cerr)
	}

	_, err = sdkssh.NewMCP(sdkssh.MCPOptions{Addr: addr})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	if !strings.Contains(protoErr.Message, "dial") {
		t.Errorf("Message = %q, want a dial failure", protoErr.Message)
	}
}

// TestNewMCP_HealthCheckPerformed pins the connect-time health probe: without
// it, a wrong-protocol endpoint would only be detected on the first real call.
func TestNewMCP_HealthCheckPerformed(t *testing.T) {
	srv := newFakeMCPServer(t)
	client := newMCPFixture(t, srv)
	_ = client

	call := srv.lastCall("health")
	if call == nil {
		t.Fatal("NewMCP did not perform a health check")
	}
	if call.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want 2.0", call.JSONRPC)
	}
}

func TestNewMCP_HealthCheckFailureIsFatal(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("health", -32000, "not ready")

	_, err := sdkssh.NewMCP(sdkssh.MCPOptions{Addr: srv.addr()})
	if err == nil {
		t.Fatal("a failing health check must abort the connect")
	}
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	if !strings.Contains(protoErr.Error(), "health check") {
		t.Errorf("error should name the health check: %v", err)
	}
}

// TestMCP_RequestEnvelopeAndIDs pins the JSON-RPC 2.0 framing: a wrong version
// string or a repeated ID breaks every conforming server.
func TestMCP_RequestEnvelopeAndIDs(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.list", map[string]interface{}{"items": []interface{}{}})
	client := newMCPFixture(t, srv)

	for i := 0; i < 3; i++ {
		if _, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{}); err != nil {
			t.Fatalf("List: %v", err)
		}
	}

	calls := srv.allCalls()
	if len(calls) < 4 { // health + 3 lists
		t.Fatalf("expected at least 4 calls, got %d", len(calls))
	}
	seen := map[int64]bool{}
	var prev int64
	for _, c := range calls {
		if c.JSONRPC != "2.0" {
			t.Errorf("jsonrpc = %q on %s", c.JSONRPC, c.Method)
		}
		if seen[c.ID] {
			t.Errorf("duplicate request id %d on %s", c.ID, c.Method)
		}
		if c.ID <= prev {
			t.Errorf("ids must increase monotonically: %d after %d", c.ID, prev)
		}
		seen[c.ID] = true
		prev = c.ID
	}
}

func TestMCPClose_Idempotent(t *testing.T) {
	srv := newFakeMCPServer(t)
	client := newMCPFixture(t, srv)

	if err := client.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// A second Close on an already-closed TCP conn reports an error from the
	// net stack; it must not panic.
	_ = client.Close()
}

// ----------------------------------------------------------------------------
// Error surfaces.
// ----------------------------------------------------------------------------

func TestMCP_ServerErrorBecomesProtocolError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.keys.get", -32004, "key not found")
	client := newMCPFixture(t, srv)

	_, err := client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{Name: "ghost"})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	// Both the code and the operator-facing message must survive.
	if !strings.Contains(protoErr.Message, "-32004") || !strings.Contains(protoErr.Message, "key not found") {
		t.Errorf("server error detail lost: %q", protoErr.Message)
	}
}

func TestMCP_MalformedResponseBecomesProtocolError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.mu.Lock()
	srv.rawResponse["ssh.keys.list"] = "{this is not json"
	srv.mu.Unlock()
	client := newMCPFixture(t, srv)

	_, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	if !strings.Contains(protoErr.Message, "decode response") {
		t.Errorf("Message = %q", protoErr.Message)
	}
	if protoErr.Unwrap() == nil {
		t.Error("the underlying decode error should be unwrappable")
	}
}

func TestMCP_WronglyTypedResultBecomesProtocolError(t *testing.T) {
	srv := newFakeMCPServer(t)
	// Well-formed envelope, but "result" is a string where an object is due.
	srv.mu.Lock()
	srv.rawResponse["ssh.keys.get"] = `{"jsonrpc":"2.0","id":2,"result":"surprise"}`
	srv.mu.Unlock()
	client := newMCPFixture(t, srv)

	_, err := client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{Name: "k"})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	if !strings.Contains(protoErr.Message, "decode result") {
		t.Errorf("Message = %q", protoErr.Message)
	}
}

func TestMCP_ConnectionClosedMidCallBecomesProtocolError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.list", map[string]interface{}{"items": []interface{}{}})
	client := newMCPFixture(t, srv)

	// Now make the server hang up instead of answering.
	srv.mu.Lock()
	srv.closeOn = "ssh.keys.list"
	srv.mu.Unlock()

	_, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	if !strings.Contains(protoErr.Message, "receive") {
		t.Errorf("Message = %q, want a receive failure", protoErr.Message)
	}
}

// ----------------------------------------------------------------------------
// Keys.
// ----------------------------------------------------------------------------

func TestMCPKeys_GenerateMethodAndParams(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.generate", map[string]interface{}{
		"scope": "user", "owner": "alice", "name": "laptop",
		"algorithm": "ed25519", "fingerprint": "SHA256:abc",
		"backend": "tpm2", "backend_key_id": "ssh-user-alice-laptop",
	})
	client := newMCPFixture(t, srv)

	key, err := client.Keys().Generate(context.Background(), sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "laptop",
		Algorithm: "rsa", RSABits: 4096, Comment: "c", Backend: "tpm2",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	p := paramsOf(t, srv, "ssh.keys.generate")
	if p["algorithm"] != "rsa" {
		t.Errorf("wire algorithm = %v", p["algorithm"])
	}
	if p["rsa_bits"] != float64(4096) {
		t.Errorf("wire rsa_bits = %v, want 4096", p["rsa_bits"])
	}
	if p["backend"] != "tpm2" {
		t.Errorf("wire backend = %v", p["backend"])
	}

	if key.BackendKeyID != "ssh-user-alice-laptop" || key.Backend != "tpm2" {
		t.Errorf("backend correlation lost: %+v", key)
	}
	if key.Fingerprint != "SHA256:abc" {
		t.Errorf("Fingerprint = %q", key.Fingerprint)
	}
}

func TestMCPKeys_GenerateError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.keys.generate", -32602, "unsupported algorithm")
	client := newMCPFixture(t, srv)

	if _, err := client.Keys().Generate(context.Background(), sdkssh.GenerateRequest{Algorithm: "rot13"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMCPKeys_ImportForwardsPEMWithoutPassphrase(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.import", map[string]interface{}{"name": "imported"})
	client := newMCPFixture(t, srv)

	pemBytes := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
	key, err := client.Keys().Import(context.Background(), sdkssh.ImportRequest{
		Scope: "user", Owner: "alice", Name: "imported", PEM: pemBytes,
	}, nil)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if key.Name != "imported" {
		t.Errorf("Name = %q", key.Name)
	}

	p := paramsOf(t, srv, "ssh.keys.import")
	// With no provider, no passphrase member may appear on the wire.
	if _, present := p["passphrase"]; present {
		t.Error("passphrase must be omitted when no provider is supplied")
	}
	if p["pem"] == nil {
		t.Error("pem missing from the wire body")
	}
}

func TestMCPKeys_ImportSendsProviderPassphrase(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.import", map[string]interface{}{"name": "imported"})
	client := newMCPFixture(t, srv)

	const secret = "correct horse battery staple"
	provider := secure.NewCallbackProvider(func(context.Context, string) ([]byte, error) {
		return []byte(secret), nil
	})

	if _, err := client.Keys().Import(context.Background(), sdkssh.ImportRequest{
		Name: "imported", PEM: []byte("pem"),
	}, provider); err != nil {
		t.Fatalf("Import: %v", err)
	}

	p := paramsOf(t, srv, "ssh.keys.import")
	encoded, ok := p["passphrase"].(string)
	if !ok {
		t.Fatalf("passphrase missing/not base64 string: %v", p["passphrase"])
	}
	// []byte marshals as base64; decode and compare so a truncation bug
	// (e.g. wrong Size()) is caught.
	raw, err := json.Marshal(p["passphrase"])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded []byte
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode passphrase: %v", err)
	}
	if string(decoded) != secret {
		t.Errorf("passphrase on wire = %q, want %q (encoded %q)", decoded, secret, encoded)
	}
}

func TestMCPKeys_ImportProviderFailureAborts(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.import", map[string]interface{}{"name": "imported"})
	client := newMCPFixture(t, srv)

	wantErr := errors.New("user cancelled")
	provider := secure.NewCallbackProvider(func(context.Context, string) ([]byte, error) {
		return nil, wantErr
	})

	_, err := client.Keys().Import(context.Background(), sdkssh.ImportRequest{
		Name: "imported", PEM: []byte("pem"),
	}, provider)
	if err == nil {
		t.Fatal("expected the provider failure to abort the import")
	}
	// Nothing may have been sent to the server.
	if srv.lastCall("ssh.keys.import") != nil {
		t.Error("import must not reach the server when the passphrase prompt fails")
	}
}

func TestMCPKeys_GetAndList(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.get", map[string]interface{}{"name": "laptop", "algorithm": "ed25519"})
	srv.ok("ssh.keys.list", map[string]interface{}{"items": []interface{}{
		map[string]interface{}{"name": "one"},
		map[string]interface{}{"name": "two"},
	}})
	client := newMCPFixture(t, srv)

	key, err := client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if key.Name != "laptop" || key.Algorithm != "ed25519" {
		t.Errorf("key = %+v", key)
	}
	gp := paramsOf(t, srv, "ssh.keys.get")
	if gp["scope"] != "user" || gp["owner"] != "alice" || gp["name"] != "laptop" {
		t.Errorf("get params = %v", gp)
	}

	keys, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{Scope: "user"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// The items envelope must be unwrapped, in order.
	if len(keys) != 2 || keys[0].Name != "one" || keys[1].Name != "two" {
		t.Errorf("keys = %+v", keys)
	}
}

func TestMCPKeys_DeleteAndExport(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.delete", map[string]interface{}{})
	srv.ok("ssh.keys.export", map[string]interface{}{
		"algorithm": "ed25519", "line": "ssh-ed25519 AAAA x", "fingerprint": "SHA256:q",
	})
	client := newMCPFixture(t, srv)

	if err := client.Keys().Delete(context.Background(), sdkssh.DeleteKeyRequest{
		Scope: "user", Owner: "alice", Name: "laptop",
	}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	dp := paramsOf(t, srv, "ssh.keys.delete")
	if dp["name"] != "laptop" {
		t.Errorf("delete params = %v", dp)
	}

	pub, err := client.Keys().ExportPublic(context.Background(), sdkssh.ExportRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("ExportPublic: %v", err)
	}
	if pub.Line != "ssh-ed25519 AAAA x" || pub.Fingerprint != "SHA256:q" {
		t.Errorf("pub = %+v", pub)
	}
}

func TestMCPKeys_DeleteError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.keys.delete", -32004, "no such key")
	client := newMCPFixture(t, srv)

	if err := client.Keys().Delete(context.Background(), sdkssh.DeleteKeyRequest{Name: "ghost"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMCPKeys_SignerForwardsDigest(t *testing.T) {
	line, sshPub := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.export", map[string]interface{}{"line": line, "algorithm": "ed25519"})
	srv.ok("ssh.keys.sign", map[string]interface{}{
		"format": "ssh-ed25519",
		"blob":   []byte("sig-blob"),
	})
	client := newMCPFixture(t, srv)

	signer, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{
		Scope: "user", Owner: "alice", Name: "laptop",
	})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if string(signer.PublicKey().Marshal()) != string(sshPub.Marshal()) {
		t.Error("signer public key does not match the exported key")
	}

	sig, err := signer.Sign(nil, []byte("digest-bytes"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Format != "ssh-ed25519" || string(sig.Blob) != "sig-blob" {
		t.Errorf("signature = %+v", sig)
	}

	p := paramsOf(t, srv, "ssh.keys.sign")
	var digest []byte
	rawDigest, _ := json.Marshal(p["digest"])
	if err := json.Unmarshal(rawDigest, &digest); err != nil {
		t.Fatalf("decode digest: %v", err)
	}
	if string(digest) != "digest-bytes" {
		t.Errorf("digest on wire = %q", digest)
	}
	if p["name"] != "laptop" || p["owner"] != "alice" {
		t.Errorf("sign addressed the wrong key: %v", p)
	}
}

func TestMCPKeys_SignerUnparsablePublicKey(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.export", map[string]interface{}{"line": "not-a-key"})
	client := newMCPFixture(t, srv)

	_, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{Name: "laptop"})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	if protoErr.Message != "parse exported public key" {
		t.Errorf("Message = %q", protoErr.Message)
	}
}

func TestMCPKeys_SignerExportFailure(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.keys.export", -32004, "no key")
	client := newMCPFixture(t, srv)

	if _, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{Name: "ghost"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMCPSigner_SignServerError(t *testing.T) {
	line, _ := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.export", map[string]interface{}{"line": line})
	srv.fail("ssh.keys.sign", -32000, "hardware locked")
	client := newMCPFixture(t, srv)

	signer, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if _, err := signer.Sign(nil, []byte("x")); err == nil {
		t.Fatal("expected the server-side signing failure to propagate")
	}
}

// ----------------------------------------------------------------------------
// KnownHosts.
// ----------------------------------------------------------------------------

func TestMCPKnownHosts_AddListRemove(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.knownHosts.add", map[string]interface{}{})
	srv.ok("ssh.knownHosts.list", map[string]interface{}{"items": []interface{}{
		map[string]interface{}{"host": "git.example.com", "fingerprint": "SHA256:pin", "source": "tofu"},
	}})
	srv.ok("ssh.knownHosts.remove", map[string]interface{}{})
	client := newMCPFixture(t, srv)

	if err := client.KnownHosts().Add(context.Background(), sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "git.example.com",
		Fingerprint: "SHA256:pin", Algorithm: "ssh-ed25519", Source: "tofu",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	ap := paramsOf(t, srv, "ssh.knownHosts.add")
	if ap["fingerprint"] != "SHA256:pin" || ap["source"] != "tofu" || ap["algorithm"] != "ssh-ed25519" {
		t.Errorf("add params = %v", ap)
	}

	pins, err := client.KnownHosts().List(context.Background(), sdkssh.ListKnownHostsRequest{Scope: "user"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(pins) != 1 || pins[0].Fingerprint != "SHA256:pin" || pins[0].Source != "tofu" {
		t.Errorf("pins = %+v", pins)
	}

	if err := client.KnownHosts().Remove(context.Background(), sdkssh.RemoveKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "git.example.com",
	}); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	rp := paramsOf(t, srv, "ssh.knownHosts.remove")
	if rp["host"] != "git.example.com" {
		t.Errorf("remove params = %v", rp)
	}
}

func TestMCPKnownHosts_ListError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.knownHosts.list", -32000, "store offline")
	client := newMCPFixture(t, srv)

	if _, err := client.KnownHosts().List(context.Background(), sdkssh.ListKnownHostsRequest{}); err == nil {
		t.Fatal("expected error")
	}
}

// TestMCPKnownHosts_VerifyComputesFingerprint pins the client-side fingerprint
// derivation. If the SDK sent the wrong digest the server would compare
// against the wrong value and could wrongly trust a host.
func TestMCPKnownHosts_VerifyComputesFingerprint(t *testing.T) {
	_, sshPub := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.ok("ssh.knownHosts.verify", map[string]interface{}{})
	client := newMCPFixture(t, srv)

	if err := client.KnownHosts().Verify(context.Background(), "user", "alice", "git.example.com", sshPub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	p := paramsOf(t, srv, "ssh.knownHosts.verify")
	if p["fingerprint"] != gossh.FingerprintSHA256(sshPub) {
		t.Errorf("fingerprint = %v, want %v", p["fingerprint"], gossh.FingerprintSHA256(sshPub))
	}
	if p["algorithm"] != sshPub.Type() {
		t.Errorf("algorithm = %v, want %v", p["algorithm"], sshPub.Type())
	}
	if p["host"] != "git.example.com" {
		t.Errorf("host = %v", p["host"])
	}
}

func TestMCPKnownHosts_VerifyRejectsNilKey(t *testing.T) {
	srv := newFakeMCPServer(t)
	client := newMCPFixture(t, srv)

	err := client.KnownHosts().Verify(context.Background(), "user", "alice", "h", nil)
	var nilErr *sdkssh.NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected *NilInputError, got %T %v", err, err)
	}
	if srv.lastCall("ssh.knownHosts.verify") != nil {
		t.Error("a nil key must be rejected before any server round-trip")
	}
}

func TestMCPKnownHosts_VerifyServerRejectionPropagates(t *testing.T) {
	_, sshPub := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.fail("ssh.knownHosts.verify", -32003, "host key mismatch")
	client := newMCPFixture(t, srv)

	// A server-side mismatch must surface as an error — never silent trust.
	err := client.KnownHosts().Verify(context.Background(), "user", "alice", "git.example.com", sshPub)
	if err == nil {
		t.Fatal("a server-reported mismatch must not be treated as trust")
	}
	if !strings.Contains(err.Error(), "host key mismatch") {
		t.Errorf("error detail lost: %v", err)
	}
}

func TestMCPKnownHosts_CallbackStripsPort(t *testing.T) {
	_, sshPub := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.ok("ssh.knownHosts.verify", map[string]interface{}{})
	client := newMCPFixture(t, srv)

	cb := client.KnownHosts().Callback(context.Background(), "user", "alice")
	if err := cb("git.example.com:2222", &net.TCPAddr{}, sshPub); err != nil {
		t.Fatalf("callback: %v", err)
	}
	p := paramsOf(t, srv, "ssh.knownHosts.verify")
	if p["host"] != "git.example.com" {
		t.Errorf("host sent as %v; the :port suffix must be stripped", p["host"])
	}
}

// ----------------------------------------------------------------------------
// AuthorizedKeys.
// ----------------------------------------------------------------------------

func TestMCPAuthorizedKeys_AddGetListRemove(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.authorizedKeys.add", map[string]interface{}{})
	srv.ok("ssh.authorizedKeys.get", map[string]interface{}{"name": "deploy", "line": "ssh-ed25519 AAAA"})
	srv.ok("ssh.authorizedKeys.list", map[string]interface{}{"items": []interface{}{
		map[string]interface{}{"name": "deploy", "options": []interface{}{"no-pty"}},
	}})
	srv.ok("ssh.authorizedKeys.remove", map[string]interface{}{})
	client := newMCPFixture(t, srv)

	if err := client.AuthorizedKeys().Add(context.Background(), sdkssh.AddAuthorizedKeyRequest{
		Scope: "service", Owner: "svc", Name: "deploy",
		Line: "ssh-ed25519 AAAA", Options: []string{"no-pty", "command=\"/bin/deploy\""},
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	ap := paramsOf(t, srv, "ssh.authorizedKeys.add")
	opts, _ := ap["options"].([]interface{})
	if len(opts) != 2 {
		t.Errorf("restriction options lost on the wire: %v", ap["options"])
	}

	entry, err := client.AuthorizedKeys().Get(context.Background(), "service", "svc", "deploy")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.Name != "deploy" {
		t.Errorf("entry = %+v", entry)
	}
	gp := paramsOf(t, srv, "ssh.authorizedKeys.get")
	if gp["scope"] != "service" || gp["owner"] != "svc" || gp["name"] != "deploy" {
		t.Errorf("get params = %v", gp)
	}

	entries, err := client.AuthorizedKeys().List(context.Background(), sdkssh.ListAuthorizedKeysRequest{Scope: "service"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || len(entries[0].Options) != 1 {
		t.Errorf("entries = %+v", entries)
	}

	if err := client.AuthorizedKeys().Remove(context.Background(), "service", "svc", "deploy"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	rp := paramsOf(t, srv, "ssh.authorizedKeys.remove")
	if rp["name"] != "deploy" || rp["scope"] != "service" {
		t.Errorf("remove params = %v", rp)
	}
}

func TestMCPAuthorizedKeys_GetNotFound(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.authorizedKeys.get", -32004, "no entry")
	client := newMCPFixture(t, srv)

	if _, err := client.AuthorizedKeys().Get(context.Background(), "service", "svc", "ghost"); err == nil {
		t.Fatal("expected error")
	}
}

func TestMCPAuthorizedKeys_ListError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.authorizedKeys.list", -32000, "store offline")
	client := newMCPFixture(t, srv)

	if _, err := client.AuthorizedKeys().List(context.Background(), sdkssh.ListAuthorizedKeysRequest{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMCPAuthorizedKeys_RemoveError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.authorizedKeys.remove", -32004, "no entry")
	client := newMCPFixture(t, srv)

	if err := client.AuthorizedKeys().Remove(context.Background(), "service", "svc", "ghost"); err == nil {
		t.Fatal("expected error")
	}
}

func TestMCPAuthorizedKeys_Emit(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.authorizedKeys.emit", map[string]interface{}{"line": "no-pty ssh-ed25519 AAAA restricted"})
	client := newMCPFixture(t, srv)

	line, err := client.AuthorizedKeys().Emit(context.Background(), sdkssh.EmitRequest{
		PublicKey: "ssh-ed25519 AAAA", Options: []string{"no-pty"}, Comment: "restricted",
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if line != "no-pty ssh-ed25519 AAAA restricted" {
		t.Errorf("line = %q", line)
	}
	p := paramsOf(t, srv, "ssh.authorizedKeys.emit")
	if p["public_key"] != "ssh-ed25519 AAAA" || p["comment"] != "restricted" {
		t.Errorf("emit params = %v", p)
	}
}

func TestMCPAuthorizedKeys_EmitError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.authorizedKeys.emit", -32602, "unparsable public key")
	client := newMCPFixture(t, srv)

	line, err := client.AuthorizedKeys().Emit(context.Background(), sdkssh.EmitRequest{PublicKey: "junk"})
	if err == nil {
		t.Fatal("expected error")
	}
	if line != "" {
		t.Errorf("a failed Emit must return an empty line, got %q", line)
	}
}

func TestMCPAuthorizedKeys_VerifyComputesFingerprint(t *testing.T) {
	_, sshPub := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.ok("ssh.authorizedKeys.verify", map[string]interface{}{"name": "deploy"})
	client := newMCPFixture(t, srv)

	entry, err := client.AuthorizedKeys().Verify(context.Background(), "service", "svc", sshPub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if entry.Name != "deploy" {
		t.Errorf("entry = %+v", entry)
	}
	p := paramsOf(t, srv, "ssh.authorizedKeys.verify")
	if p["fingerprint"] != gossh.FingerprintSHA256(sshPub) {
		t.Errorf("fingerprint = %v", p["fingerprint"])
	}
	if p["algorithm"] != sshPub.Type() {
		t.Errorf("algorithm = %v", p["algorithm"])
	}
}

func TestMCPAuthorizedKeys_VerifyRejectsNilKey(t *testing.T) {
	srv := newFakeMCPServer(t)
	client := newMCPFixture(t, srv)

	_, err := client.AuthorizedKeys().Verify(context.Background(), "service", "svc", nil)
	var nilErr *sdkssh.NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected *NilInputError, got %T %v", err, err)
	}
	if srv.lastCall("ssh.authorizedKeys.verify") != nil {
		t.Error("a nil key must be rejected before any server round-trip")
	}
}

func TestMCPAuthorizedKeys_VerifyRejectionPropagates(t *testing.T) {
	_, sshPub := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.fail("ssh.authorizedKeys.verify", -32004, "key not authorized")
	client := newMCPFixture(t, srv)

	entry, err := client.AuthorizedKeys().Verify(context.Background(), "service", "svc", sshPub)
	if err == nil {
		t.Fatal("an unauthorized key must not be accepted")
	}
	if entry != nil {
		t.Error("no entry may be returned on rejection")
	}
}

// ----------------------------------------------------------------------------
// Unsupported capabilities.
// ----------------------------------------------------------------------------

func TestMCPConsole_Unsupported(t *testing.T) {
	srv := newFakeMCPServer(t)
	client := newMCPFixture(t, srv)

	_, err := client.Console(context.Background(),
		sdkssh.ConsoleConnectRequest{Host: "h", User: "u"}, sdkssh.ConsoleConfig{})
	var unsupported *sdkssh.ConsoleUnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("expected *ConsoleUnsupportedError, got %T %v", err, err)
	}
	if unsupported.Transport != "mcp" {
		t.Errorf("Transport = %q", unsupported.Transport)
	}
}

func TestMCPSession_DialUnsupported(t *testing.T) {
	srv := newFakeMCPServer(t)
	client := newMCPFixture(t, srv)

	_, err := client.Session().Dial(context.Background(), sdkssh.SessionDialRequest{Host: "h", User: "u"})
	var ni *sdkssh.NotImplementedError
	if !errors.As(err, &ni) {
		t.Fatalf("expected *NotImplementedError, got %T %v", err, err)
	}
	if ni.Transport != "mcp" {
		t.Errorf("Transport = %q", ni.Transport)
	}
}
