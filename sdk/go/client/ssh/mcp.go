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

// MCP (Model Context Protocol) transport for the SSH SDK client.
//
// NewMCP dials the unified qrdb MCP server's Streamable HTTP endpoint and
// returns a Client that issues ssh.keys.*, ssh.knownHosts.*, and
// ssh.authorizedKeys.* calls as MCP "tools/call" requests, using
// pkg/mcptool.Client for the connection, TLS/mTLS setup, protocol handshake,
// tool-call framing, and go-qrdb wire.ErrorEnvelope decoding — the same
// machinery pkg/api/transport/mcp.Transport uses to reach that server for
// the rest of the xkms SDK. This package builds on pkg/mcptool rather than
// on pkg/api/transport/mcp directly because pkg/api/mcp's Server holds an
// sdk/go/client/ssh.Client for its own SSH sub-system (Config.SSHClient):
// importing pkg/api/transport/mcp here would cycle back through it, since
// that package imports pkg/api/mcp for its xkms-specific error-code
// classification. pkg/mcptool is the shared leaf both packages depend on
// instead of duplicating the session and tool-call code — see its doc
// comment.
//
// There is deliberately no second hand-rolled MCP client here: the raw
// line-framed JSON-RPC-over-TCP plane this package spoke previously was
// retired with pkg/api/mcp's standalone listener (see that package's doc
// comment), and this client now reaches the sole remaining MCP surface, the
// unified server's tool-call plane.
//
// # Error classification
//
// call (below) reconstructs this package's own typed errors --
// *NotFoundError, *DuplicateError, *MismatchError, *InvalidRequestError,
// *NotImplementedError, *AuthError -- from a failed call's
// *mcptool.RPCError.WireCode, the raw go-qrdb wire.Code classification,
// mirroring how the REST transport's decodeErrorResponse reconstructs them
// from an HTTP status, and how sdk/go/client/ssh/mcp_status.go's
// JSONRPCCodeForError classifies the same store errors for the (now
// retired) raw JSON-RPC framing. The server's mapSSHError
// (pkg/api/mcp/errors_ssh.go) delegates to that same shared classify()
// table (rest_status_dispatch.go) via JSONRPCCodeForError, and
// pkg/apimodule's keyOpCodeToWire carries JSONRPCCodeNotFound/Duplicate/
// Mismatch onto wire.CodeNotFound/CodeAlreadyExists/CodeFailedPrecondition
// respectively (go-xkms#792) -- so a not-found, a duplicate, and a host-key
// mismatch each reach this client as their own distinct WireCode, not one
// shared bucket.
//
// The one real gap: go-qrdb's wire.ErrorEnvelope carries only Code, Status,
// Message, and Tool (pkg/mcptool, "the accepted wire-contract bridge
// import" -- this SDK does not own that contract to extend it), where the
// REST transport's JSON error body also carries Resource/Host/Expected/
// Received. *NotFoundError/*DuplicateError reconstruct with Message but no
// Resource; *MismatchError has no Message field at all, so
// mcpKnownHostsClient.Verify fills in Host and Received from its own
// parameters (it already has both without the server's help) and Expected
// has no substitute -- it is the one field MCP genuinely cannot carry
// today. See classifyMCPError's doc comment for the mechanics.
//
// Session.Dial is supported: it resolves the signing and host-key-
// verification RPCs over MCP, then dials the target SSH host directly from
// this process — it needs no bidirectional stream from the MCP connection.
// Console is not supported over this transport — an interactive console
// needs a stateful bidirectional byte stream that MCP tool calls do not
// model.
package ssh

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	wire "github.com/jeremyhahn/go-qrdb/pkg/api/mcp/wire"

	apitransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/mcptool"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// MCPOptions configures the MCP transport Client. Only Addr is required;
// all other fields are optional.
type MCPOptions struct {
	// Addr is the host:port of the unified qrdb MCP server's Streamable
	// HTTP endpoint (e.g. "xkms.example.com:9444"). Required.
	Addr string

	// TLSConfig enables TLS when non-nil. nil means plain HTTP (not
	// recommended for production deployments).
	TLSConfig *tls.Config
}

// NewMCP constructs an MCP SSH Client, connects to Addr (negotiating the
// MCP protocol version and confirming the session with a health-check tool
// call), and returns the connected client. The caller must call Close() to
// release the underlying HTTP transport.
//
// Returns *NilInputError when Addr is empty.
func NewMCP(opts MCPOptions) (Client, error) {
	if opts.Addr == "" {
		return nil, &NilInputError{Field: "Addr"}
	}

	cfg := apitransport.DefaultConfig()
	cfgOpts := []apitransport.Option{apitransport.WithAddress(opts.Addr)}
	if opts.TLSConfig != nil {
		cfgOpts = append(cfgOpts, apitransport.WithTLSConfig(opts.TLSConfig))
	}
	if err := apitransport.ApplyOptions(cfg, cfgOpts...); err != nil {
		return nil, &ProtocolError{Message: "configure mcp transport", Err: err}
	}

	client := mcptool.NewClient(cfg)
	if connErr := client.Connect(context.Background()); connErr != nil {
		return nil, &ProtocolError{Message: "connect " + opts.Addr, Err: connErr}
	}

	// Confirm the session is usable before handing it to the caller, the
	// same guarantee the retired TCP transport gave with its post-dial
	// health probe.
	if err := client.Call(context.Background(), "health", nil, nil); err != nil {
		return nil, errors.Join(&ProtocolError{Message: "health check after connect", Err: err}, client.Close())
	}

	return &mcpClient{client: client}, nil
}

// ----------------------------------------------------------------------------
// mcpClient — top-level Client.
// ----------------------------------------------------------------------------

// mcpClient is the MCP-transport SSH Client. It forwards every call through
// a pkg/mcptool.Client, which owns the Streamable HTTP session.
type mcpClient struct {
	client *mcptool.Client
}

func (c *mcpClient) Keys() KeysClient             { return &mcpKeysClient{c: c} }
func (c *mcpClient) KnownHosts() KnownHostsClient { return &mcpKnownHostsClient{c: c} }
func (c *mcpClient) AuthorizedKeys() AuthorizedKeysClient {
	return &mcpAuthorizedKeysClient{c: c}
}
func (c *mcpClient) Session() SessionClient { return &mcpSessionClient{c: c} }

// Console is unsupported over MCP: a tool call cannot carry an interactive
// byte stream.
func (c *mcpClient) Console(_ context.Context, _ ConsoleConnectRequest, _ ConsoleConfig) (ConsoleSession, error) {
	return nil, &ConsoleUnsupportedError{Transport: "mcp"}
}

func (c *mcpClient) Close() error {
	return c.client.Close()
}

// call invokes method as an MCP tool call and unmarshals the result into
// out. out may be nil when the caller does not need the response body. Any
// failure from the underlying client (connection, protocol, or tool-level)
// is wrapped in a *ProtocolError so callers keep a single error type to
// match against; classifyMCPError (below) reconstructs this package's own
// typed error as .Err when the failure is a classified *mcptool.RPCError,
// so errors.As also reaches *NotFoundError/*DuplicateError/*MismatchError-
// adjacent conditions (as *InvalidRequestError; see the package doc
// comment), *AuthError, or *NotImplementedError. An unclassified failure
// (*mcptool.ReceiveError, *mcptool.MarshalError, *mcptool.UnmarshalError,
// *mcptool.EnvelopeMissingError, or mcptool.ErrNotConnected) is wrapped
// unchanged, exactly as before.
func (c *mcpClient) call(ctx context.Context, method string, params, out interface{}) error {
	if err := c.client.Call(ctx, method, params, out); err != nil {
		return &ProtocolError{Message: method, Err: classifyMCPError(err)}
	}
	return nil
}

// classifyMCPError reconstructs this package's typed errors from a
// *mcptool.RPCError's WireCode, mirroring decodeErrorResponse's HTTP-status
// switch (rest.go) for the MCP transport and JSONRPCCodeForError's table
// (mcp_status.go) in reverse. A non-*RPCError failure (or an *RPCError
// whose WireCode this switch does not recognize) is returned unchanged.
//
// go-qrdb's wire.ErrorEnvelope (pkg/mcptool) carries only Code, Status,
// Message, and Tool -- there is no room for the Resource/Host/Expected/
// Received detail the REST transport's richer JSON error body carries, and
// this SDK does not own that contract to extend it (see pkg/mcptool's doc
// comment: it is "the accepted wire-contract bridge import"). So
// *NotFoundError and *DuplicateError here carry Message but not Resource,
// and *MismatchError -- which has no Message field at all, only Host/
// Expected/Received -- comes back with none of its fields set; Host and
// Received are populated by the one call site that can supply them locally
// (mcpKnownHostsClient.Verify, which already knows both without the
// server's help), and Expected has no substitute: it is the one piece of
// this error class MCP genuinely cannot carry today.
func classifyMCPError(err error) error {
	var rpcErr *mcptool.RPCError
	if !errors.As(err, &rpcErr) {
		return err
	}
	switch rpcErr.WireCode {
	case wire.CodeUnauthenticated:
		return &AuthError{StatusCode: 401, Message: rpcErr.Message}
	case wire.CodePermissionDenied:
		return &AuthError{StatusCode: 403, Message: rpcErr.Message}
	case wire.CodeUnimplemented:
		return &NotImplementedError{Transport: "mcp", Op: rpcErr.Message}
	case wire.CodeUnavailable:
		return &ServerError{StatusCode: 503, Message: rpcErr.Message}
	case wire.CodeNotFound:
		return &NotFoundError{Message: rpcErr.Message}
	case wire.CodeAlreadyExists:
		return &DuplicateError{Message: rpcErr.Message}
	case wire.CodeFailedPrecondition:
		// See the doc comment above: Host/Received are filled in by
		// mcpKnownHostsClient.Verify from its own parameters, not from the
		// wire; Expected has no source.
		return &MismatchError{}
	case wire.CodeInvalidArgument:
		return &InvalidRequestError{Message: rpcErr.Message}
	default:
		return err
	}
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
	body := mcpImportWire{
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
		body.Passphrase = make([]byte, buf.Size())
		copy(body.Passphrase, buf.Bytes())
		buf.Destroy()
	}
	var out Key
	err := k.c.call(ctx, "ssh.keys.import", body, &out)
	// Wipe the passphrase copy regardless of outcome.
	secure.Wipe(body.Passphrase)
	body.Passphrase = nil
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
// A mismatch on the server side is surfaced as a *ProtocolError wrapping a
// *MismatchError.
//
// classifyMCPError cannot populate *MismatchError's Host/Expected/Received
// fields from the wire (go-qrdb's wire.ErrorEnvelope has no room for them;
// see mcp.go's package doc comment), so Verify fills in Host and Received
// itself here -- it already has both from its own parameters, no server
// round-trip needed. Expected (the pin's actual stored key) has no
// substitute and stays empty; that is a real, documented gap, not an
// oversight.
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
	err := k.c.call(ctx, "ssh.knownHosts.verify", params, nil)
	if err == nil {
		return nil
	}
	var mismatchErr *MismatchError
	if errors.As(err, &mismatchErr) {
		mismatchErr.Host = host
		mismatchErr.Received = gossh.FingerprintSHA256(received)
	}
	return err
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
// Session sub-client.
// ----------------------------------------------------------------------------

// mcpSessionClient implements SessionClient over MCP. Dial needs no
// bidirectional stream from the MCP connection: it only uses MCP for the
// signing and host-key-verification RPCs, then dials the SSH connection
// directly from this process. Only Console needs a persistent byte stream
// (see mcpClient.Console), which MCP tool calls cannot carry.
type mcpSessionClient struct {
	c *mcpClient
}

// Dial resolves the authentication key to a forward-signing proxy and the
// target host to a wire-verified callback, both over MCP, then dials the
// SSH connection directly from this process. See dialNetworkSession for the
// shared implementation and its host-key trust model.
func (s *mcpSessionClient) Dial(ctx context.Context, req SessionDialRequest) (Session, error) {
	return dialNetworkSession(ctx, &mcpKeysClient{c: s.c}, &mcpKnownHostsClient{c: s.c}, req)
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
