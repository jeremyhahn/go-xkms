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

package local

import (
	"bytes"
	"errors"
	"net"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
)

// DialAgent dials the system ssh-agent at sockPath and returns the
// signers it currently serves.
//
// Lifetime: the returned signers are backed by an agent-protocol client
// wrapping the freshly dialed net.Conn — each Sign call round-trips a
// request to the agent over that connection. DialAgent deliberately does
// NOT close the connection before returning; doing so would make every
// returned signer unusable. The connection is left open for the lifetime
// of the returned signers and is reclaimed by the OS when the process
// exits (or, for a longer-lived caller, when the underlying file
// descriptor is otherwise closed out from under it). Callers that need
// deterministic cleanup should keep the dial short-lived — call DialAgent
// immediately before use rather than caching its result — which is the
// intended usage pattern here (see SignerForPublicKey and ResolveSigner,
// both of which dial fresh on every call).
//
// Returns *AgentUnavailableError if sockPath is empty or the socket
// cannot be dialed.
func DialAgent(sockPath string) ([]ssh.Signer, error) {
	if sockPath == "" {
		return nil, &AgentUnavailableError{Path: sockPath, Err: errors.New("no agent socket configured")}
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, &AgentUnavailableError{Path: sockPath, Err: err}
	}

	client := sshagent.NewClient(conn)
	signers, err := client.Signers()
	if err != nil {
		return nil, errors.Join(&AgentUnavailableError{Path: sockPath, Err: err}, conn.Close())
	}

	return signers, nil
}

// SignerForPublicKey dials the agent at sockPath and returns the signer
// matching pub. This is the preferred resolution path whenever the agent
// is configured and pub was resolved from a paired .pub file, because it
// is the only way to obtain a working signer for hardware-backed
// identities (e.g. "sk-" security-key types) whose private half never
// leaves the token the agent is talking to.
//
// Returns *NilInputError if pub is nil, *AgentUnavailableError if the
// agent cannot be reached, and *AgentKeyNotFoundError if the agent is
// reachable but does not currently serve a signer for pub.
func SignerForPublicKey(sockPath string, pub ssh.PublicKey) (ssh.Signer, error) {
	if pub == nil {
		return nil, &NilInputError{Field: "pub"}
	}

	signers, err := DialAgent(sockPath)
	if err != nil {
		return nil, err
	}

	want := pub.Marshal()
	for _, s := range signers {
		if bytes.Equal(s.PublicKey().Marshal(), want) {
			return s, nil
		}
	}

	return nil, &AgentKeyNotFoundError{Fingerprint: keys.Fingerprint(pub)}
}

// SignerForFingerprint dials the agent at sockPath and returns the signer
// whose public key has the given OpenSSH SHA256 fingerprint (the form
// reported by `ssh-add -l`, e.g. "SHA256:..."). It is the resolution path
// for agent-held keys referenced by fingerprint alone — keys with no
// on-disk identity file to derive a public key from.
//
// Returns *NilInputError if fingerprint is empty, *AgentUnavailableError
// if the agent cannot be reached, and *AgentKeyNotFoundError if the agent
// is reachable but serves no key with that fingerprint.
func SignerForFingerprint(sockPath, fingerprint string) (ssh.Signer, error) {
	if fingerprint == "" {
		return nil, &NilInputError{Field: "fingerprint"}
	}

	signers, err := DialAgent(sockPath)
	if err != nil {
		return nil, err
	}

	for _, s := range signers {
		if keys.Fingerprint(s.PublicKey()) == fingerprint {
			return s, nil
		}
	}

	return nil, &AgentKeyNotFoundError{Fingerprint: fingerprint}
}
