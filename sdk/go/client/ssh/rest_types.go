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

import "net"

// restImportRequest is the wire form of ImportRequest with a
// passphrase field included. The client populates PassphraseB64 via
// base64-encoding a secure.Buffer; the server decodes with a custom
// json.Unmarshaler that lands the bytes directly in a *secure.Buffer
// without ever materializing a Go string.
type restImportRequest struct {
	Scope         string `json:"scope"`
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	Comment       string `json:"comment,omitempty"`
	PEM           []byte `json:"pem"`
	PassphraseB64 string `json:"passphrase_b64,omitempty"`
}

// restSignRequest is the JSON body of POST /keys/.../sign.
type restSignRequest struct {
	Digest []byte `json:"digest"`
}

// restSignResponse is the JSON body returned by the sign endpoint. It
// mirrors the *ssh.Signature fields directly.
type restSignResponse struct {
	Format string `json:"format"`
	Blob   []byte `json:"blob"`
	Rest   []byte `json:"rest,omitempty"`
}

// restVerifyRequest carries the payload for POST /known-hosts/{host}/verify.
type restVerifyRequest struct {
	Scope       string `json:"scope"`
	Owner       string `json:"owner"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm,omitempty"`
}

// restAuthVerifyRequest carries the payload for POST /authorized-keys/verify.
type restAuthVerifyRequest struct {
	Scope       string `json:"scope"`
	Owner       string `json:"owner"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm,omitempty"`
}

// restEmitResponse is the JSON body returned by POST /authorized-keys/emit.
type restEmitResponse struct {
	Line string `json:"line"`
}

// restKeyList is the envelope returned by GET /keys.
type restKeyList struct {
	Items []*Key `json:"items"`
}

// restPinList is the envelope returned by GET /known-hosts.
type restPinList struct {
	Items []*Pin `json:"items"`
}

// restAuthorizedList is the envelope returned by GET /authorized-keys.
type restAuthorizedList struct {
	Items []*AuthorizedEntry `json:"items"`
}

// stripCallbackPort removes the trailing ":port" from the hostname
// x/crypto/ssh passes to a HostKeyCallback so pins persist per-host.
// Identical semantics to pkg/ssh/known_hosts.stripPort; duplicated here
// to avoid depending on that unexported symbol.
func stripCallbackPort(hostname string) string {
	host, _, err := net.SplitHostPort(hostname)
	if err != nil {
		return hostname
	}
	return host
}
