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

package ssh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// RESTOptions configures the REST (HTTP/JSON) transport Client.
type RESTOptions struct {
	// BaseURL is the xkmsd base URL, e.g. "https://xkms.example.com".
	// Required. Trailing slashes are tolerated.
	BaseURL string

	// HTTPClient is the HTTP client used for all requests. nil selects
	// http.DefaultClient. Callers that need custom TLS configuration,
	// timeouts, or middleware install them by supplying a pre-built
	// http.Client here.
	HTTPClient *http.Client

	// AuthToken is an optional bearer token forwarded in the
	// Authorization header. Empty disables authentication headers.
	AuthToken string
}

// NewREST constructs the REST-transport Client. Returns *NilInputError
// when BaseURL is empty.
func NewREST(opts RESTOptions) (Client, error) {
	trimmed := strings.TrimRight(opts.BaseURL, "/")
	if trimmed == "" {
		return nil, &NilInputError{Field: "BaseURL"}
	}
	if _, err := url.Parse(trimmed); err != nil {
		return nil, &InvalidRequestError{Message: "BaseURL: " + err.Error()}
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	return &restClient{
		base:   trimmed,
		hc:     hc,
		token:  opts.AuthToken,
		ctxKey: sshAPIPrefix,
	}, nil
}

// sshAPIPrefix is the path prefix under BaseURL that hosts every SSH
// endpoint. Centralized so tests and handlers agree on the shape.
const sshAPIPrefix = "/xkms/v1/ssh"

// restClient is the REST-transport Client.
type restClient struct {
	base   string
	hc     *http.Client
	token  string
	ctxKey string // path prefix, "/xkms/v1/ssh"
}

// Keys returns the REST Keys sub-client.
func (c *restClient) Keys() KeysClient { return &restKeysClient{c: c} }

// KnownHosts returns the REST KnownHosts sub-client.
func (c *restClient) KnownHosts() KnownHostsClient { return &restKnownHostsClient{c: c} }

// AuthorizedKeys returns the REST AuthorizedKeys sub-client.
func (c *restClient) AuthorizedKeys() AuthorizedKeysClient {
	return &restAuthorizedKeysClient{c: c}
}

// Session returns the REST Session sub-client.
func (c *restClient) Session() SessionClient { return &restSessionClient{c: c} }

// Console is not supported by the REST/QUIC Go client: the interactive console
// over HTTP is served by the WebSocket bridge (NewConsoleWSHandler) and consumed
// by an HTTP/WS client or sdk/ts in the browser, not this request/response
// client.
func (c *restClient) Console(_ context.Context, _ ConsoleConnectRequest, _ ConsoleConfig) (ConsoleSession, error) {
	return nil, &ConsoleUnsupportedError{Transport: "rest"}
}

// Close releases any resources held by the client. The REST transport
// holds no long-lived server-side state, so this is a no-op.
func (c *restClient) Close() error { return nil }

// do performs an HTTP request, attaches auth, and returns the response
// body bytes for non-error responses or a typed error for error
// responses. Status-code routing uses the shared table.
func (c *restClient) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, &ProtocolError{Message: "encode request", Err: err}
		}
		reqBody = bytes.NewReader(buf)
	}

	u := c.base + c.ctxKey + path
	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return nil, &ProtocolError{Message: "build request", Err: err}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, &ProtocolError{Message: "round-trip", Err: err}
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Debug("ssh: failed to close HTTP response body", "error", cerr)
		}
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &ProtocolError{Message: "read response", Err: err}
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return respBody, nil
	}
	return nil, decodeErrorResponse(resp.StatusCode, respBody)
}

// doWithQuery is a convenience around do for GET requests that need
// query parameters.
func (c *restClient) doWithQuery(ctx context.Context, path string, q url.Values) ([]byte, error) {
	if len(q) > 0 {
		path = path + "?" + q.Encode()
	}
	return c.do(ctx, http.MethodGet, path, nil)
}

// decodeErrorResponse converts a non-2xx response into the matching
// typed error. Body is expected to be a JSON envelope of the form
// {"error": "...", "message": "...", "details": {...}} — missing fields
// are tolerated.
func decodeErrorResponse(status int, body []byte) error {
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		// Best-effort: a non-JSON or empty error body just leaves env zero-valued,
		// which the switch below already handles via empty Resource/Message. Still
		// worth knowing about, so it is logged rather than dropped.
		slog.Debug("ssh: failed to decode error response envelope", "status", status, "error", err)
	}
	msg := env.Message
	if msg == "" {
		msg = env.Error
	}
	switch status {
	case http.StatusNotFound:
		return &NotFoundError{Resource: env.Resource, Message: msg}
	case http.StatusConflict:
		if env.Resource == "known_hosts" && env.Expected != "" {
			return &MismatchError{
				Host:     env.Host,
				Expected: env.Expected,
				Received: env.Received,
			}
		}
		return &DuplicateError{Resource: env.Resource, Message: msg}
	case http.StatusBadRequest:
		return &InvalidRequestError{Message: msg}
	case http.StatusUnauthorized, http.StatusForbidden:
		return &AuthError{StatusCode: status, Message: msg}
	case http.StatusNotImplemented:
		return &NotImplementedError{Transport: "rest", Op: msg}
	}
	if status >= 500 {
		return &ServerError{StatusCode: status, Message: msg}
	}
	return &ServerError{StatusCode: status, Message: msg}
}

// errorEnvelope is the canonical JSON shape the server emits on
// non-2xx responses. The server handlers produce it via writeSSHError.
type errorEnvelope struct {
	Error    string `json:"error,omitempty"`
	Message  string `json:"message,omitempty"`
	Resource string `json:"resource,omitempty"`
	Host     string `json:"host,omitempty"`
	Expected string `json:"expected,omitempty"`
	Received string `json:"received,omitempty"`
}

// ----------------------------------------------------------------------------
// Keys sub-client.
// ----------------------------------------------------------------------------

// restKeysClient implements KeysClient over REST.
type restKeysClient struct {
	c *restClient
}

// Generate calls POST /keys.
func (k *restKeysClient) Generate(ctx context.Context, req GenerateRequest) (*Key, error) {
	body, err := k.c.do(ctx, http.MethodPost, "/keys", req)
	if err != nil {
		return nil, err
	}
	var out Key
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &ProtocolError{Message: "decode Key", Err: err}
	}
	return &out, nil
}

// Import calls POST /keys/import. When provider is non-nil the
// passphrase is fetched into a copy in the wire body (encoding/json
// base64-encodes the []byte field on the wire); the copy is wiped
// before the call returns regardless of outcome, and the source
// secure.Buffer is destroyed as soon as the copy is made.
func (k *restKeysClient) Import(ctx context.Context, req ImportRequest, provider secure.PassphraseProvider) (*Key, error) {
	wire := restImportRequest{
		Scope:   req.Scope,
		Owner:   req.Owner,
		Name:    req.Name,
		Comment: req.Comment,
		PEM:     req.PEM,
	}
	if provider != nil {
		pwBuf, err := provider.Passphrase(ctx, "SSH key passphrase: ")
		if err != nil {
			return nil, err
		}
		pass, err := secure.CopyOut(pwBuf)
		pwBuf.Destroy()
		if err != nil {
			return nil, err
		}
		// wire.Passphrase is this same slice (not a copy of it, unlike a
		// string conversion), so the wipe erases what k.c.do marshaled, on
		// every path out of Import.
		defer secure.Wipe(pass)
		wire.Passphrase = pass
	}

	body, err := k.c.do(ctx, http.MethodPost, "/keys/import", wire)
	if err != nil {
		return nil, err
	}
	var out Key
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &ProtocolError{Message: "decode Key", Err: err}
	}
	return &out, nil
}

// Get calls GET /keys/{scope}/{owner}/{name}.
func (k *restKeysClient) Get(ctx context.Context, req GetKeyRequest) (*Key, error) {
	path := fmt.Sprintf("/keys/%s/%s/%s",
		url.PathEscape(req.Scope), url.PathEscape(req.Owner), url.PathEscape(req.Name))
	body, err := k.c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var out Key
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &ProtocolError{Message: "decode Key", Err: err}
	}
	return &out, nil
}

// List calls GET /keys?scope=&owner=.
func (k *restKeysClient) List(ctx context.Context, req ListKeysRequest) ([]*Key, error) {
	q := url.Values{}
	if req.Scope != "" {
		q.Set("scope", req.Scope)
	}
	if req.Owner != "" {
		q.Set("owner", req.Owner)
	}
	body, err := k.c.doWithQuery(ctx, "/keys", q)
	if err != nil {
		return nil, err
	}
	var out restKeyList
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &ProtocolError{Message: "decode key list", Err: err}
	}
	return out.Items, nil
}

// Delete calls DELETE /keys/{scope}/{owner}/{name}.
func (k *restKeysClient) Delete(ctx context.Context, req DeleteKeyRequest) error {
	path := fmt.Sprintf("/keys/%s/%s/%s",
		url.PathEscape(req.Scope), url.PathEscape(req.Owner), url.PathEscape(req.Name))
	_, err := k.c.do(ctx, http.MethodDelete, path, nil)
	return err
}

// ExportPublic calls GET /keys/{scope}/{owner}/{name}/public.
func (k *restKeysClient) ExportPublic(ctx context.Context, req ExportRequest) (*PublicKey, error) {
	path := fmt.Sprintf("/keys/%s/%s/%s/public",
		url.PathEscape(req.Scope), url.PathEscape(req.Owner), url.PathEscape(req.Name))
	body, err := k.c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var out PublicKey
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &ProtocolError{Message: "decode PublicKey", Err: err}
	}
	return &out, nil
}

// Signer returns a remote-signer proxy that forwards digests to the
// server. The public key is fetched once at construction via
// ExportPublic so PublicKey() calls are zero-cost.
func (k *restKeysClient) Signer(ctx context.Context, req GetKeyRequest) (gossh.Signer, error) {
	pub, err := k.ExportPublic(ctx, ExportRequest(req))
	if err != nil {
		return nil, err
	}
	sshPub, err := parseExportedPublicKey(pub.Line)
	if err != nil {
		return nil, err
	}
	return &restSigner{
		c:     k.c,
		scope: req.Scope,
		owner: req.Owner,
		name:  req.Name,
		pub:   sshPub,
	}, nil
}

// restSigner is the remote-signer proxy. Each Sign call POSTs the
// digest to /keys/{scope}/{owner}/{name}/sign and returns the server's
// signature.
type restSigner struct {
	c     *restClient
	scope string
	owner string
	name  string
	pub   gossh.PublicKey
}

// PublicKey returns the cached public key.
func (s *restSigner) PublicKey() gossh.PublicKey { return s.pub }

// Sign forwards the digest to the server and returns the assembled
// *ssh.Signature.
func (s *restSigner) Sign(_ io.Reader, data []byte) (*gossh.Signature, error) {
	path := fmt.Sprintf("/keys/%s/%s/%s/sign",
		url.PathEscape(s.scope), url.PathEscape(s.owner), url.PathEscape(s.name))
	req := restSignRequest{Digest: data}
	body, err := s.c.do(context.Background(), http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}
	var out restSignResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &ProtocolError{Message: "decode signature", Err: err}
	}
	return &gossh.Signature{
		Format: out.Format,
		Blob:   out.Blob,
		Rest:   out.Rest,
	}, nil
}

// ----------------------------------------------------------------------------
// KnownHosts sub-client.
// ----------------------------------------------------------------------------

// restKnownHostsClient implements KnownHostsClient over REST.
type restKnownHostsClient struct {
	c *restClient
}

// Add calls POST /known-hosts.
func (k *restKnownHostsClient) Add(ctx context.Context, req AddKnownHostRequest) error {
	_, err := k.c.do(ctx, http.MethodPost, "/known-hosts", req)
	return err
}

// List calls GET /known-hosts?scope=&owner=.
func (k *restKnownHostsClient) List(ctx context.Context, req ListKnownHostsRequest) ([]*Pin, error) {
	q := url.Values{}
	if req.Scope != "" {
		q.Set("scope", req.Scope)
	}
	if req.Owner != "" {
		q.Set("owner", req.Owner)
	}
	body, err := k.c.doWithQuery(ctx, "/known-hosts", q)
	if err != nil {
		return nil, err
	}
	var out restPinList
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &ProtocolError{Message: "decode pin list", Err: err}
	}
	return out.Items, nil
}

// Remove calls DELETE /known-hosts/{host}?scope=&owner=.
func (k *restKnownHostsClient) Remove(ctx context.Context, req RemoveKnownHostRequest) error {
	path := fmt.Sprintf("/known-hosts/%s", url.PathEscape(req.Host))
	q := url.Values{}
	if req.Scope != "" {
		q.Set("scope", req.Scope)
	}
	if req.Owner != "" {
		q.Set("owner", req.Owner)
	}
	if len(q) > 0 {
		path = path + "?" + q.Encode()
	}
	_, err := k.c.do(ctx, http.MethodDelete, path, nil)
	return err
}

// Verify calls POST /known-hosts/{host}/verify with the presented host
// public key in authorized_keys format. The server parses it and
// compares it against the stored pin's full public key via the
// canonical known_hosts.Verify — the fingerprint is never trusted from
// the wire.
func (k *restKnownHostsClient) Verify(ctx context.Context, scope, owner, host string, received gossh.PublicKey) error {
	if received == nil {
		return &NilInputError{Field: "received"}
	}
	path := fmt.Sprintf("/known-hosts/%s/verify", url.PathEscape(host))
	req := restVerifyRequest{
		Scope:     scope,
		Owner:     owner,
		PublicKey: strings.TrimRight(string(gossh.MarshalAuthorizedKey(received)), "\n"),
	}
	_, err := k.c.do(ctx, http.MethodPost, path, req)
	return err
}

// Callback returns an ssh.HostKeyCallback that delegates to Verify
// over the wire for each inbound host key.
func (k *restKnownHostsClient) Callback(ctx context.Context, scope, owner string) gossh.HostKeyCallback {
	return func(hostname string, _ net.Addr, key gossh.PublicKey) error {
		host := stripCallbackPort(hostname)
		return k.Verify(ctx, scope, owner, host, key)
	}
}

// ----------------------------------------------------------------------------
// AuthorizedKeys sub-client.
// ----------------------------------------------------------------------------

// restAuthorizedKeysClient implements AuthorizedKeysClient over REST.
type restAuthorizedKeysClient struct {
	c *restClient
}

// Add calls POST /authorized-keys.
func (a *restAuthorizedKeysClient) Add(ctx context.Context, req AddAuthorizedKeyRequest) error {
	_, err := a.c.do(ctx, http.MethodPost, "/authorized-keys", req)
	return err
}

// Get calls GET /authorized-keys/{scope}/{owner}/{name}.
func (a *restAuthorizedKeysClient) Get(ctx context.Context, scope, owner, name string) (*AuthorizedEntry, error) {
	path := fmt.Sprintf("/authorized-keys/%s/%s/%s",
		url.PathEscape(scope), url.PathEscape(owner), url.PathEscape(name))
	body, err := a.c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var out AuthorizedEntry
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &ProtocolError{Message: "decode AuthorizedEntry", Err: err}
	}
	return &out, nil
}

// List calls GET /authorized-keys?scope=&owner=.
func (a *restAuthorizedKeysClient) List(ctx context.Context, req ListAuthorizedKeysRequest) ([]*AuthorizedEntry, error) {
	q := url.Values{}
	if req.Scope != "" {
		q.Set("scope", req.Scope)
	}
	if req.Owner != "" {
		q.Set("owner", req.Owner)
	}
	body, err := a.c.doWithQuery(ctx, "/authorized-keys", q)
	if err != nil {
		return nil, err
	}
	var out restAuthorizedList
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &ProtocolError{Message: "decode authorized list", Err: err}
	}
	return out.Items, nil
}

// Remove calls DELETE /authorized-keys/{scope}/{owner}/{name}.
func (a *restAuthorizedKeysClient) Remove(ctx context.Context, scope, owner, name string) error {
	path := fmt.Sprintf("/authorized-keys/%s/%s/%s",
		url.PathEscape(scope), url.PathEscape(owner), url.PathEscape(name))
	_, err := a.c.do(ctx, http.MethodDelete, path, nil)
	return err
}

// Emit calls POST /authorized-keys/emit.
func (a *restAuthorizedKeysClient) Emit(ctx context.Context, req EmitRequest) (string, error) {
	body, err := a.c.do(ctx, http.MethodPost, "/authorized-keys/emit", req)
	if err != nil {
		return "", err
	}
	var out restEmitResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", &ProtocolError{Message: "decode Emit response", Err: err}
	}
	return out.Line, nil
}

// Verify calls POST /authorized-keys/verify with the received
// fingerprint.
func (a *restAuthorizedKeysClient) Verify(ctx context.Context, scope, owner string, received gossh.PublicKey) (*AuthorizedEntry, error) {
	if received == nil {
		return nil, &NilInputError{Field: "received"}
	}
	req := restAuthVerifyRequest{
		Scope:       scope,
		Owner:       owner,
		Fingerprint: gossh.FingerprintSHA256(received),
		Algorithm:   received.Type(),
	}
	body, err := a.c.do(ctx, http.MethodPost, "/authorized-keys/verify", req)
	if err != nil {
		return nil, err
	}
	var out AuthorizedEntry
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &ProtocolError{Message: "decode AuthorizedEntry", Err: err}
	}
	return &out, nil
}

// ----------------------------------------------------------------------------
// Session sub-client.
// ----------------------------------------------------------------------------

// restSessionClient implements SessionClient over REST.
type restSessionClient struct {
	c *restClient
}

// Dial resolves the authentication key to a forward-signing proxy and the
// target host to a wire-verified callback, both over REST, then dials the
// SSH connection directly from this process. See dialNetworkSession for the
// shared implementation and its host-key trust model.
func (s *restSessionClient) Dial(ctx context.Context, req SessionDialRequest) (Session, error) {
	return dialNetworkSession(ctx, &restKeysClient{c: s.c}, &restKnownHostsClient{c: s.c}, req)
}

// Ensure the interface wiring is compile-time checked.
var (
	_ Client               = (*restClient)(nil)
	_ KeysClient           = (*restKeysClient)(nil)
	_ KnownHostsClient     = (*restKnownHostsClient)(nil)
	_ AuthorizedKeysClient = (*restAuthorizedKeysClient)(nil)
	_ SessionClient        = (*restSessionClient)(nil)
	_ gossh.Signer         = (*restSigner)(nil)
)

// Ensure errors referenced above are not accidentally dropped.
var (
	_ error = (*NotFoundError)(nil)
	_ error = (*DuplicateError)(nil)
	_ error = (*MismatchError)(nil)
	_ error = (*InvalidRequestError)(nil)
	_ error = (*AuthError)(nil)
	_ error = (*ServerError)(nil)
	_ error = (*ProtocolError)(nil)
)
