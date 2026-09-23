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

package mcp

import sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"

// SSHSignParams carries inputs for the ssh.keys.sign method. Scope,
// Owner, and Name identify the key; Digest is the raw bytes to sign.
type SSHSignParams struct {
	Scope  string `json:"scope"`
	Owner  string `json:"owner"`
	Name   string `json:"name"`
	Digest []byte `json:"digest"`
}

// SSHSignResult carries the signature returned by ssh.keys.sign.
// Fields mirror gossh.Signature.
type SSHSignResult struct {
	Format string `json:"format"`
	Blob   []byte `json:"blob"`
	Rest   []byte `json:"rest,omitempty"`
}

// SSHImportParams carries inputs for ssh.keys.import. Passphrase is
// optional raw bytes forwarded to the enclave unsealer; only secure
// when the MCP connection uses TLS.
type SSHImportParams struct {
	Scope      string `json:"scope"`
	Owner      string `json:"owner"`
	Name       string `json:"name"`
	PEM        []byte `json:"pem"`
	Comment    string `json:"comment,omitempty"`
	Passphrase []byte `json:"passphrase,omitempty"`
}

// SSHKnownHostsVerifyParams carries inputs for ssh.knownHosts.verify.
// PublicKey is the presented host key as an authorized_keys-format line;
// the server parses it and compares it against the stored pin's full
// public key — the caller's claimed fingerprint is never trusted.
type SSHKnownHostsVerifyParams struct {
	Scope     string `json:"scope"`
	Owner     string `json:"owner"`
	Host      string `json:"host"`
	PublicKey string `json:"public_key"`
}

// SSHAuthorizedKeysGetParams carries inputs for ssh.authorizedKeys.get.
// The REST transport encodes Scope/Owner/Name in the URL path; MCP
// carries them in the JSON body.
type SSHAuthorizedKeysGetParams struct {
	Scope string `json:"scope"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// SSHAuthorizedKeysRemoveParams carries inputs for
// ssh.authorizedKeys.remove.
type SSHAuthorizedKeysRemoveParams struct {
	Scope string `json:"scope"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// SSHAuthorizedKeysVerifyParams carries inputs for
// ssh.authorizedKeys.verify. Fingerprint is the SHA-256 fingerprint
// of the received public key in "SHA256:<base64>" form.
type SSHAuthorizedKeysVerifyParams struct {
	Scope       string `json:"scope"`
	Owner       string `json:"owner"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm,omitempty"`
}

// SSHKeyListResult is the result envelope for ssh.keys.list.
type SSHKeyListResult struct {
	Items []*sdkssh.Key `json:"items"`
}

// SSHPinListResult is the result envelope for ssh.knownHosts.list.
type SSHPinListResult struct {
	Items []*sdkssh.Pin `json:"items"`
}

// SSHAuthorizedListResult is the result envelope for
// ssh.authorizedKeys.list.
type SSHAuthorizedListResult struct {
	Items []*sdkssh.AuthorizedEntry `json:"items"`
}

// SSHEmitResult is the result type for ssh.authorizedKeys.emit.
type SSHEmitResult struct {
	Line string `json:"line"`
}

// SSHSuccessResult is a generic result for SSH operations that produce
// no payload (add, remove, verify-success).
type SSHSuccessResult struct {
	Success bool `json:"success"`
}
