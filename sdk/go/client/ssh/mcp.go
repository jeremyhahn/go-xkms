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

// MCP (JSON-RPC 2.0 over TCP) transport for the SSH SDK client.
//
// NewMCP dials the xkmsd MCP server and returns a Client that issues
// JSON-RPC 2.0 requests over a persistent TCP (or TLS) connection with
// newline-delimited JSON framing — the same wire format used by the
// existing pkg/api/transport/mcp Transport.
//
// Session.Dial is not supported over this transport. Interactive SSH
// sessions require a stateful bidirectional stream that JSON-RPC 2.0
// over TCP does not model. Use the embedded transport for local
// sessions.
package ssh

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	gossh "golang.org/x/crypto/ssh"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// MCPOptions configures the MCP (JSON-RPC 2.0 over TCP) transport
// Client. Only Addr is required; all other fields are optional.
type MCPOptions struct {
	// Addr is the TCP address of the xkmsd MCP server (e.g.
	// "xkms.example.com:9444"). Required.
	Addr string

	// TLSConfig enables TLS when non-nil. nil means plain TCP (not
	// recommended for production deployments).
	TLSConfig *tls.Config
}

// NewMCP constructs an MCP SSH Client, dials Addr, performs a health
// check, and returns the connected client. The caller must call
// Close() to release the TCP connection.
//
// Returns *NilInputError when Addr is empty.
func NewMCP(opts MCPOptions) (Client, error) {
	if opts.Addr == "" {
		return nil, &NilInputError{Field: "Addr"}
	}

	var conn net.Conn
	var dialErr error
	if opts.TLSConfig != nil {
		dialer := &tls.Dialer{Config: opts.TLSConfig}
		conn, dialErr = dialer.DialContext(context.Background(), "tcp", opts.Addr)
	} else {
		conn, dialErr = net.Dial("tcp", opts.Addr)
	}
	if dialErr != nil {
		return nil, &ProtocolError{Message: "dial " + opts.Addr, Err: dialErr}
	}

	c := &mcpClient{
		conn:    conn,
		enc:     json.NewEncoder(conn),
		scanner: bufio.NewScanner(conn),
	}
	// Allow up to 10 MB for large responses (consistent with the MCP transport).
	c.scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	// Health check: ensures the server is alive and speaks our protocol.
	if err := c.call(context.Background(), "health", nil, nil); err != nil {
		_ = conn.Close()
		return nil, &ProtocolError{Message: "health check after connect", Err: err}
	}

	return c, nil
}

// ----------------------------------------------------------------------------
// mcpClient — top-level Client.
// ----------------------------------------------------------------------------

// mcpClient is the MCP-transport SSH Client. It owns a single TCP
// connection serialised with write/read mutexes.
type mcpClient struct {
	conn    net.Conn
	enc     *json.Encoder
	scanner *bufio.Scanner
	nextID  atomic.Int64
	writeMu sync.Mutex
	readMu  sync.Mutex
}

func (c *mcpClient) Keys() KeysClient             { return &mcpKeysClient{c: c} }
func (c *mcpClient) KnownHosts() KnownHostsClient { return &mcpKnownHostsClient{c: c} }
func (c *mcpClient) AuthorizedKeys() AuthorizedKeysClient {
	return &mcpAuthorizedKeysClient{c: c}
}
func (c *mcpClient) Session() SessionClient { return &mcpSessionClient{} }

// Console is unsupported over MCP: JSON-RPC request/response cannot carry an
// interactive byte stream.
func (c *mcpClient) Console(_ context.Context, _ ConsoleConnectRequest, _ ConsoleConfig) (ConsoleSession, error) {
	return nil, &ConsoleUnsupportedError{Transport: "mcp"}
}

func (c *mcpClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// call sends a JSON-RPC 2.0 request and unmarshals the result into
// out. out may be nil when the caller does not need the response body.
func (c *mcpClient) call(ctx context.Context, method string, params, out interface{}) error {
	id := c.nextID.Add(1)

	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return &ProtocolError{Message: "marshal params for " + method, Err: err}
		}
		rawParams = b
	}

	req := &mcpRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  rawParams,
		ID:      id,
	}

	c.writeMu.Lock()
	sendErr := c.enc.Encode(req)
	c.writeMu.Unlock()
	if sendErr != nil {
		return &ProtocolError{Message: "send " + method, Err: sendErr}
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if !c.scanner.Scan() {
		readErr := c.scanner.Err()
		if readErr == nil {
			readErr = &ConnectionClosedError{}
		}
		return &ProtocolError{Message: "receive " + method, Err: readErr}
	}

	var resp mcpResponse
	if err := json.Unmarshal(c.scanner.Bytes(), &resp); err != nil {
		return &ProtocolError{Message: "decode response for " + method, Err: err}
	}

	if resp.Error != nil {
		return &ProtocolError{
			Message: fmt.Sprintf("server error %d: %s", resp.Error.Code, resp.Error.Message),
		}
	}

	if out != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return &ProtocolError{Message: "decode result for " + method, Err: err}
		}
	}

	return nil
}

// ----------------------------------------------------------------------------
// JSON-RPC 2.0 envelope types (unexported; wire-compatible with the
// pkg/api/mcp server and pkg/api/transport/mcp transport).
// ----------------------------------------------------------------------------

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      int64           `json:"id"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mcpRPCError    `json:"error,omitempty"`
	ID      int64           `json:"id,omitempty"`
}

type mcpRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ----------------------------------------------------------------------------
// Wire types (unexported) — must match the JSON tags in
// pkg/api/mcp/types_ssh.go and pkg/api/mcp/handlers_ssh.go exactly.
// ----------------------------------------------------------------------------

// mcpImportWire is the JSON body for ssh.keys.import.
type mcpImportWire struct {
	Scope      string `json:"scope"`
	Owner      string `json:"owner"`
	Name       string `json:"name"`
	PEM        []byte `json:"pem"`
	Comment    string `json:"comment,omitempty"`
	Passphrase []byte `json:"passphrase,omitempty"`
}

// mcpSignParams is the JSON body for ssh.keys.sign.
type mcpSignParams struct {
	Scope  string `json:"scope"`
	Owner  string `json:"owner"`
	Name   string `json:"name"`
	Digest []byte `json:"digest"`
}

// mcpSignResult mirrors SSHSignResult / gossh.Signature fields.
type mcpSignResult struct {
	Format string `json:"format"`
	Blob   []byte `json:"blob"`
	Rest   []byte `json:"rest,omitempty"`
}

// mcpKeyList is the envelope returned by ssh.keys.list.
type mcpKeyList struct {
	Items []*Key `json:"items"`
}

// mcpPinList is the envelope returned by ssh.knownHosts.list.
type mcpPinList struct {
	Items []*Pin `json:"items"`
}

// mcpAuthorizedList is the envelope returned by ssh.authorizedKeys.list.
type mcpAuthorizedList struct {
	Items []*AuthorizedEntry `json:"items"`
}

// mcpEmitResult mirrors SSHEmitResult.
type mcpEmitResult struct {
	Line string `json:"line"`
}

// mcpAuthorizedGetParams is the JSON body for ssh.authorizedKeys.get.
type mcpAuthorizedGetParams struct {
	Scope string `json:"scope"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// mcpAuthorizedRemoveParams is the JSON body for
// ssh.authorizedKeys.remove.
type mcpAuthorizedRemoveParams struct {
	Scope string `json:"scope"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// mcpKnownHostVerifyParams is the JSON body for ssh.knownHosts.verify.
// PublicKey is the presented host key as an authorized_keys-format line.
type mcpKnownHostVerifyParams struct {
	Scope     string `json:"scope"`
	Owner     string `json:"owner"`
	Host      string `json:"host"`
	PublicKey string `json:"public_key"`
}

// mcpAuthVerifyParams is the JSON body for ssh.authorizedKeys.verify.
type mcpAuthVerifyParams struct {
	Scope       string `json:"scope"`
	Owner       string `json:"owner"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm,omitempty"`
}

// ----------------------------------------------------------------------------
// Keys sub-client.
// ----------------------------------------------------------------------------

// mcpKeysClient implements KeysClient over MCP.
type mcpKeysClient struct {
	c *mcpClient
}

// Generate calls ssh.keys.generate.
func (k *mcpKeysClient) Generate(ctx context.Context, req GenerateRequest) (*Key, error) {
	var out Key
	if err := k.c.call(ctx, "ssh.keys.generate", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Import calls ssh.keys.import. When provider is non-nil the passphrase
// is fetched and included in the wire body as raw bytes; it is wiped
// from the local buffer before the call returns regardless of outcome.
func (k *mcpKeysClient) Import(ctx context.Context, req ImportRequest, provider secure.PassphraseProvider) (*Key, error) {
	wire := mcpImportWire{
		Scope:   req.Scope,
		Owner:   req.Owner,
		Name:    req.Name,
		PEM:     req.PEM,
		Comment: req.Comment,
	}
	if provider != nil {
		buf, err := provider.Passphrase(ctx, "SSH key passphrase: ")
		if err != nil {
			return nil, err
		}
		wire.Passphrase = make([]byte, buf.Size())
		copy(wire.Passphrase, buf.Bytes())
		buf.Destroy()
	}
	var out Key
	err := k.c.call(ctx, "ssh.keys.import", wire, &out)
	// Wipe the passphrase copy regardless of outcome.
	secure.Wipe(wire.Passphrase)
	wire.Passphrase = nil
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Get calls ssh.keys.get.
func (k *mcpKeysClient) Get(ctx context.Context, req GetKeyRequest) (*Key, error) {
	var out Key
	if err := k.c.call(ctx, "ssh.keys.get", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// List calls ssh.keys.list.
func (k *mcpKeysClient) List(ctx context.Context, req ListKeysRequest) ([]*Key, error) {
	var out mcpKeyList
	if err := k.c.call(ctx, "ssh.keys.list", req, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// Delete calls ssh.keys.delete.
func (k *mcpKeysClient) Delete(ctx context.Context, req DeleteKeyRequest) error {
	return k.c.call(ctx, "ssh.keys.delete", req, nil)
}

// ExportPublic calls ssh.keys.export.
func (k *mcpKeysClient) ExportPublic(ctx context.Context, req ExportRequest) (*PublicKey, error) {
	var out PublicKey
	if err := k.c.call(ctx, "ssh.keys.export", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Signer constructs a remote-signer proxy. The public key is fetched
// once via ExportPublic; subsequent Sign calls forward the digest to
// the server via ssh.keys.sign.
func (k *mcpKeysClient) Signer(ctx context.Context, req GetKeyRequest) (gossh.Signer, error) {
	pub, err := k.ExportPublic(ctx, ExportRequest(req))
	if err != nil {
		return nil, err
	}
	sshPub, err := parseExportedPublicKey(pub.Line)
	if err != nil {
		return nil, err
	}
	return &mcpSigner{
		c:     k.c,
		scope: req.Scope,
		owner: req.Owner,
		name:  req.Name,
		pub:   sshPub,
	}, nil
}

// mcpSigner forwards Sign calls to the MCP server's ssh.keys.sign
// method. PublicKey is cached at construction time.
type mcpSigner struct {
	c     *mcpClient
	scope string
	owner string
	name  string
	pub   gossh.PublicKey
}

// PublicKey returns the cached public key.
func (s *mcpSigner) PublicKey() gossh.PublicKey { return s.pub }

// Sign forwards the digest to the server and returns the assembled
// gossh.Signature. The rand parameter is ignored — signing is
// performed server-side.
func (s *mcpSigner) Sign(_ io.Reader, data []byte) (*gossh.Signature, error) {
	var result mcpSignResult
	if err := s.c.call(context.Background(), "ssh.keys.sign", mcpSignParams{
		Scope:  s.scope,
		Owner:  s.owner,
		Name:   s.name,
		Digest: data,
	}, &result); err != nil {
		return nil, err
	}
	return &gossh.Signature{
		Format: result.Format,
		Blob:   result.Blob,
		Rest:   result.Rest,
	}, nil
}

// ----------------------------------------------------------------------------
// KnownHosts sub-client.
// ----------------------------------------------------------------------------

// mcpKnownHostsClient implements KnownHostsClient over MCP.
type mcpKnownHostsClient struct {
	c *mcpClient
}

// Add calls ssh.knownHosts.add.
func (k *mcpKnownHostsClient) Add(ctx context.Context, req AddKnownHostRequest) error {
	return k.c.call(ctx, "ssh.knownHosts.add", req, nil)
}

// List calls ssh.knownHosts.list.
func (k *mcpKnownHostsClient) List(ctx context.Context, req ListKnownHostsRequest) ([]*Pin, error) {
	var out mcpPinList
	if err := k.c.call(ctx, "ssh.knownHosts.list", req, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// Remove calls ssh.knownHosts.remove.
func (k *mcpKnownHostsClient) Remove(ctx context.Context, req RemoveKnownHostRequest) error {
	return k.c.call(ctx, "ssh.knownHosts.remove", req, nil)
}

// Verify sends the presented host public key, in authorized_keys
// format, to ssh.knownHosts.verify. The server parses it and compares
// it against the stored pin's full public key via the canonical
// known_hosts.Verify — the fingerprint is never trusted from the wire.
// A mismatch on the server side is surfaced as a *ProtocolError.
func (k *mcpKnownHostsClient) Verify(ctx context.Context, scope, owner, host string, received gossh.PublicKey) error {
	if received == nil {
		return &NilInputError{Field: "received"}
	}
	params := mcpKnownHostVerifyParams{
		Scope:     scope,
		Owner:     owner,
		Host:      host,
		PublicKey: strings.TrimRight(string(gossh.MarshalAuthorizedKey(received)), "\n"),
	}
	return k.c.call(ctx, "ssh.knownHosts.verify", params, nil)
}

// Callback returns an ssh.HostKeyCallback that delegates to Verify for
// each inbound host key. The callback strips the port suffix that
// x/crypto/ssh adds to the hostname before comparing against stored
// pins.
func (k *mcpKnownHostsClient) Callback(ctx context.Context, scope, owner string) gossh.HostKeyCallback {
	return func(hostname string, _ net.Addr, key gossh.PublicKey) error {
		return k.Verify(ctx, scope, owner, stripCallbackPort(hostname), key)
	}
}

// ----------------------------------------------------------------------------
// AuthorizedKeys sub-client.
// ----------------------------------------------------------------------------

// mcpAuthorizedKeysClient implements AuthorizedKeysClient over MCP.
type mcpAuthorizedKeysClient struct {
	c *mcpClient
}

// Add calls ssh.authorizedKeys.add.
func (a *mcpAuthorizedKeysClient) Add(ctx context.Context, req AddAuthorizedKeyRequest) error {
	return a.c.call(ctx, "ssh.authorizedKeys.add", req, nil)
}

// Get calls ssh.authorizedKeys.get.
func (a *mcpAuthorizedKeysClient) Get(ctx context.Context, scope, owner, name string) (*AuthorizedEntry, error) {
	var out AuthorizedEntry
	if err := a.c.call(ctx, "ssh.authorizedKeys.get", mcpAuthorizedGetParams{
		Scope: scope,
		Owner: owner,
		Name:  name,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// List calls ssh.authorizedKeys.list.
func (a *mcpAuthorizedKeysClient) List(ctx context.Context, req ListAuthorizedKeysRequest) ([]*AuthorizedEntry, error) {
	var out mcpAuthorizedList
	if err := a.c.call(ctx, "ssh.authorizedKeys.list", req, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// Remove calls ssh.authorizedKeys.remove.
func (a *mcpAuthorizedKeysClient) Remove(ctx context.Context, scope, owner, name string) error {
	return a.c.call(ctx, "ssh.authorizedKeys.remove", mcpAuthorizedRemoveParams{
		Scope: scope,
		Owner: owner,
		Name:  name,
	}, nil)
}

// Emit calls ssh.authorizedKeys.emit.
func (a *mcpAuthorizedKeysClient) Emit(ctx context.Context, req EmitRequest) (string, error) {
	var out mcpEmitResult
	if err := a.c.call(ctx, "ssh.authorizedKeys.emit", req, &out); err != nil {
		return "", err
	}
	return out.Line, nil
}

// Verify computes the SHA-256 fingerprint of received and calls
// ssh.authorizedKeys.verify with it. The matching AuthorizedEntry is
// returned on success.
func (a *mcpAuthorizedKeysClient) Verify(ctx context.Context, scope, owner string, received gossh.PublicKey) (*AuthorizedEntry, error) {
	if received == nil {
		return nil, &NilInputError{Field: "received"}
	}
	var out AuthorizedEntry
	if err := a.c.call(ctx, "ssh.authorizedKeys.verify", mcpAuthVerifyParams{
		Scope:       scope,
		Owner:       owner,
		Fingerprint: gossh.FingerprintSHA256(received),
		Algorithm:   received.Type(),
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ----------------------------------------------------------------------------
// Session sub-client stub.
// ----------------------------------------------------------------------------

// mcpSessionClient implements SessionClient over MCP. Dial is not
// supported — interactive SSH sessions require a stateful bidirectional
// stream that cannot be modelled over JSON-RPC 2.0 request/response.
type mcpSessionClient struct{}

// Dial returns *NotImplementedError for the MCP transport.
func (s *mcpSessionClient) Dial(_ context.Context, _ SessionDialRequest) (Session, error) {
	return nil, &NotImplementedError{
		Transport: "mcp",
		Op:        "Session.Dial (use embedded transport for local sessions)",
	}
}

// ----------------------------------------------------------------------------
// Compile-time interface checks.
// ----------------------------------------------------------------------------

var (
	_ Client               = (*mcpClient)(nil)
	_ KeysClient           = (*mcpKeysClient)(nil)
	_ KnownHostsClient     = (*mcpKnownHostsClient)(nil)
	_ AuthorizedKeysClient = (*mcpAuthorizedKeysClient)(nil)
	_ SessionClient        = (*mcpSessionClient)(nil)
	_ gossh.Signer         = (*mcpSigner)(nil)
)
