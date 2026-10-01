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

// SSH handlers for the MCP JSON-RPC 2.0 server.
//
// Methods are registered in server.go under the namespaces:
//
//	ssh.keys.*           — key lifecycle and signing
//	ssh.knownHosts.*     — host-key pin management
//	ssh.authorizedKeys.* — authorized_keys management
//
// Every handler delegates directly to the sdkssh.Client stored in
// s.sshClient. Session.Dial is not supported over the MCP transport;
// clients that need interactive sessions should use the embedded or
// gRPC transport instead.
//
// Every error this file returns passes through mapSSHError (errors_ssh.go)
// before reaching InvokeMethod, so it carries a *KeyOpError the unified
// server's mcpToolHandler (pkg/apimodule/module_mcp.go) can classify onto
// go-qrdb's wire.Code envelope instead of collapsing to a bare "internal
// error" with the detail discarded (go-xkms#792).
package mcp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"

	gossh "golang.org/x/crypto/ssh"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// ErrSSHNotConfigured is returned by SSH methods when the MCP server
// was constructed without an SSH client.
var ErrSSHNotConfigured = errors.New("mcp/ssh: client not configured")

// Required-field sentinels for SSH handlers whose params decode
// successfully but omit a field the operation cannot proceed without. Each
// is wrapped in a *SSHInvalidParamsError at its call site so it reports the
// same JSON-RPC Invalid params code as a decode failure.
var (
	// ErrSSHDigestRequired is returned by ssh.keys.sign when params.Digest
	// is empty.
	ErrSSHDigestRequired = errors.New("digest is required")

	// ErrSSHHostRequired is returned by ssh.knownHosts.verify when
	// params.Host is empty.
	ErrSSHHostRequired = errors.New("host is required")

	// ErrSSHPublicKeyRequired is returned by ssh.knownHosts.verify when
	// params.PublicKey is empty.
	ErrSSHPublicKeyRequired = errors.New("public_key is required")

	// ErrSSHFingerprintRequired is returned by ssh.authorizedKeys.verify
	// when params.Fingerprint is empty.
	ErrSSHFingerprintRequired = errors.New("fingerprint is required")
)

// checkSSHClient returns ErrSSHNotConfigured when s.sshClient is nil.
func (s *Server) checkSSHClient() error {
	if s.sshClient == nil {
		return ErrSSHNotConfigured
	}
	return nil
}

// ------------------------------------------------------------------
// Keys.
// ------------------------------------------------------------------

// handleSSHKeysGenerate handles ssh.keys.generate.
func (s *Server) handleSSHKeysGenerate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params sdkssh.GenerateRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	key, err := s.sshClient.Keys().Generate(ctx, params)
	if err != nil {
		return nil, mapSSHError(err)
	}
	return key, nil
}

// handleSSHKeysImport handles ssh.keys.import. When the Passphrase
// field is non-empty it is wrapped in a secure.Buffer and forwarded to
// the underlying key store. The connection MUST use TLS to protect the
// passphrase bytes in transit.
func (s *Server) handleSSHKeysImport(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params SSHImportParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	importReq := sdkssh.ImportRequest{
		Scope:   params.Scope,
		Owner:   params.Owner,
		Name:    params.Name,
		PEM:     params.PEM,
		Comment: params.Comment,
	}
	var provider secure.PassphraseProvider
	if len(params.Passphrase) > 0 {
		provider = &sshStaticPassphraseProvider{data: params.Passphrase}
	}
	key, err := s.sshClient.Keys().Import(ctx, importReq, provider)
	if err != nil {
		return nil, mapSSHError(err)
	}
	return key, nil
}

// handleSSHKeysList handles ssh.keys.list.
func (s *Server) handleSSHKeysList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params sdkssh.ListKeysRequest
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &SSHInvalidParamsError{Err: err}}
		}
	}
	keys, err := s.sshClient.Keys().List(ctx, params)
	if err != nil {
		return nil, mapSSHError(err)
	}
	return SSHKeyListResult{Items: keys}, nil
}

// handleSSHKeysGet handles ssh.keys.get.
func (s *Server) handleSSHKeysGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params sdkssh.GetKeyRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	key, err := s.sshClient.Keys().Get(ctx, params)
	if err != nil {
		return nil, mapSSHError(err)
	}
	return key, nil
}

// handleSSHKeysDelete handles ssh.keys.delete.
func (s *Server) handleSSHKeysDelete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params sdkssh.DeleteKeyRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	if err := s.sshClient.Keys().Delete(ctx, params); err != nil {
		return nil, mapSSHError(err)
	}
	return SSHSuccessResult{Success: true}, nil
}

// handleSSHKeysExport handles ssh.keys.export. It returns only the
// public half of the key — no private material leaves the server.
func (s *Server) handleSSHKeysExport(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params sdkssh.ExportRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	pub, err := s.sshClient.Keys().ExportPublic(ctx, params)
	if err != nil {
		return nil, mapSSHError(err)
	}
	return pub, nil
}

// handleSSHKeysSign handles ssh.keys.sign. It acquires an
// enclave-backed Signer via the SSH client and signs the digest
// supplied by the caller. The digest MUST be a pre-hashed value; no
// additional hashing is performed server-side.
func (s *Server) handleSSHKeysSign(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params SSHSignParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	if len(params.Digest) == 0 {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: ErrSSHDigestRequired})
	}
	signer, err := s.sshClient.Keys().Signer(ctx, sdkssh.GetKeyRequest{
		Scope: params.Scope,
		Owner: params.Owner,
		Name:  params.Name,
	})
	if err != nil {
		return nil, mapSSHError(err)
	}
	sig, err := signer.Sign(rand.Reader, params.Digest)
	if err != nil {
		return nil, mapSSHError(err)
	}
	return SSHSignResult{Format: sig.Format, Blob: sig.Blob, Rest: sig.Rest}, nil
}

// ------------------------------------------------------------------
// Known hosts.
// ------------------------------------------------------------------

// handleSSHKnownHostsAdd handles ssh.knownHosts.add.
func (s *Server) handleSSHKnownHostsAdd(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params sdkssh.AddKnownHostRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	if err := s.sshClient.KnownHosts().Add(ctx, params); err != nil {
		return nil, mapSSHError(err)
	}
	return SSHSuccessResult{Success: true}, nil
}

// handleSSHKnownHostsList handles ssh.knownHosts.list.
func (s *Server) handleSSHKnownHostsList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params sdkssh.ListKnownHostsRequest
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &SSHInvalidParamsError{Err: err}}
		}
	}
	pins, err := s.sshClient.KnownHosts().List(ctx, params)
	if err != nil {
		return nil, mapSSHError(err)
	}
	return SSHPinListResult{Items: pins}, nil
}

// handleSSHKnownHostsRemove handles ssh.knownHosts.remove.
func (s *Server) handleSSHKnownHostsRemove(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params sdkssh.RemoveKnownHostRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	if err := s.sshClient.KnownHosts().Remove(ctx, params); err != nil {
		return nil, mapSSHError(err)
	}
	return SSHSuccessResult{Success: true}, nil
}

// handleSSHKnownHostsVerify handles ssh.knownHosts.verify. It parses the
// caller-supplied host public key (authorized_keys format) and delegates
// to known_hosts.Verify via the SSH client, which performs a full
// public-key comparison against the stored pin — never a caller-claimed
// fingerprint. A key mismatch returns a *known_hosts.MismatchError so the
// caller can detect MITM-indicating key changes.
func (s *Server) handleSSHKnownHostsVerify(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params SSHKnownHostsVerifyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	if params.Host == "" {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: ErrSSHHostRequired})
	}
	if params.PublicKey == "" {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: ErrSSHPublicKeyRequired})
	}
	pub, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(params.PublicKey))
	if perr != nil {
		return nil, mapSSHError(&sdkssh.InvalidPublicKeyError{Host: params.Host, Err: perr})
	}
	if err := s.sshClient.KnownHosts().Verify(ctx, params.Scope, params.Owner, params.Host, pub); err != nil {
		return nil, mapSSHError(err)
	}
	return SSHSuccessResult{Success: true}, nil
}

// ------------------------------------------------------------------
// Authorized keys.
// ------------------------------------------------------------------

// handleSSHAuthorizedKeysAdd handles ssh.authorizedKeys.add.
func (s *Server) handleSSHAuthorizedKeysAdd(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params sdkssh.AddAuthorizedKeyRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	if err := s.sshClient.AuthorizedKeys().Add(ctx, params); err != nil {
		return nil, mapSSHError(err)
	}
	return SSHSuccessResult{Success: true}, nil
}

// handleSSHAuthorizedKeysGet handles ssh.authorizedKeys.get.
func (s *Server) handleSSHAuthorizedKeysGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params SSHAuthorizedKeysGetParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	entry, err := s.sshClient.AuthorizedKeys().Get(ctx, params.Scope, params.Owner, params.Name)
	if err != nil {
		return nil, mapSSHError(err)
	}
	return entry, nil
}

// handleSSHAuthorizedKeysList handles ssh.authorizedKeys.list.
func (s *Server) handleSSHAuthorizedKeysList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params sdkssh.ListAuthorizedKeysRequest
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &SSHInvalidParamsError{Err: err}}
		}
	}
	entries, err := s.sshClient.AuthorizedKeys().List(ctx, params)
	if err != nil {
		return nil, mapSSHError(err)
	}
	return SSHAuthorizedListResult{Items: entries}, nil
}

// handleSSHAuthorizedKeysRemove handles ssh.authorizedKeys.remove.
func (s *Server) handleSSHAuthorizedKeysRemove(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params SSHAuthorizedKeysRemoveParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	if err := s.sshClient.AuthorizedKeys().Remove(ctx, params.Scope, params.Owner, params.Name); err != nil {
		return nil, mapSSHError(err)
	}
	return SSHSuccessResult{Success: true}, nil
}

// handleSSHAuthorizedKeysEmit handles ssh.authorizedKeys.emit.
func (s *Server) handleSSHAuthorizedKeysEmit(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params sdkssh.EmitRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	line, err := s.sshClient.AuthorizedKeys().Emit(ctx, params)
	if err != nil {
		return nil, mapSSHError(err)
	}
	return SSHEmitResult{Line: line}, nil
}

// handleSSHAuthorizedKeysVerify handles ssh.authorizedKeys.verify. It
// walks the authorized entries for (scope, owner) and returns the
// first entry whose public-key fingerprint matches the caller's.
func (s *Server) handleSSHAuthorizedKeysVerify(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if err := s.checkSSHClient(); err != nil {
		return nil, mapSSHError(err)
	}
	var params SSHAuthorizedKeysVerifyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: err})
	}
	if params.Fingerprint == "" {
		return nil, mapSSHError(&SSHInvalidParamsError{Err: ErrSSHFingerprintRequired})
	}
	entries, err := s.sshClient.AuthorizedKeys().List(ctx, sdkssh.ListAuthorizedKeysRequest{
		Scope: params.Scope,
		Owner: params.Owner,
	})
	if err != nil {
		return nil, mapSSHError(err)
	}
	for _, entry := range entries {
		pub, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(entry.Line))
		if perr != nil {
			continue
		}
		if gossh.FingerprintSHA256(pub) == params.Fingerprint {
			return entry, nil
		}
	}
	return nil, mapSSHError(&SSHNotFoundError{Resource: "authorized_key"})
}

// ------------------------------------------------------------------
// MCP-layer typed errors.
// ------------------------------------------------------------------

// SSHInvalidParamsError is returned by SSH handlers when the JSON
// params cannot be decoded or a required field is missing.
type SSHInvalidParamsError struct {
	Err error
}

// Error implements the error interface.
func (e *SSHInvalidParamsError) Error() string {
	if e.Err == nil {
		return "mcp/ssh: invalid params"
	}
	return "mcp/ssh: invalid params: " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *SSHInvalidParamsError) Unwrap() error { return e.Err }

// SSHNotFoundError is returned by verify handlers when the requested
// resource is not present in the store.
type SSHNotFoundError struct {
	Resource string
	Host     string
}

// Error implements the error interface.
func (e *SSHNotFoundError) Error() string {
	if e.Host != "" {
		return "mcp/ssh: " + e.Resource + " not found: " + e.Host
	}
	return "mcp/ssh: " + e.Resource + " not found"
}

// ------------------------------------------------------------------
// Internal helpers.
// ------------------------------------------------------------------

// sshStaticPassphraseProvider implements secure.PassphraseProvider
// over a pre-fetched byte slice. Used by the MCP import handler when
// the caller supplies a non-empty Passphrase field.
type sshStaticPassphraseProvider struct {
	data []byte
}

// Passphrase copies the data into a new secure.Buffer owned by the
// caller. The caller must call Destroy on the returned Buffer.
func (p *sshStaticPassphraseProvider) Passphrase(_ context.Context, _ string) (*secure.Buffer, error) {
	buf, err := secure.NewBuffer(len(p.data))
	if err != nil {
		return nil, err
	}
	if err := buf.WithBytes(func(b []byte) error {
		copy(b, p.data)
		return nil
	}); err != nil {
		buf.Destroy()
		return nil, err
	}
	return buf, nil
}

// compile-time guard: sshStaticPassphraseProvider must satisfy
// secure.PassphraseProvider.
var _ secure.PassphraseProvider = (*sshStaticPassphraseProvider)(nil)
