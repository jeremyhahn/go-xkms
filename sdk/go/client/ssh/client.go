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
	"context"

	gossh "golang.org/x/crypto/ssh"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Client is the top-level SDK surface. Concrete implementations wrap
// exactly one transport (embedded, REST, gRPC).
type Client interface {
	// Keys returns the key-management sub-client.
	Keys() KeysClient

	// KnownHosts returns the host-key pin sub-client.
	KnownHosts() KnownHostsClient

	// AuthorizedKeys returns the authorized_keys sub-client.
	AuthorizedKeys() AuthorizedKeysClient

	// Session returns the session-dial sub-client.
	Session() SessionClient

	// Close releases any resources held by the Client (e.g., storage
	// handles for the embedded transport). Idempotent.
	Close() error
}

// KeysClient manages SSH keys. Import accepts a PassphraseProvider so
// encrypted PEMs are handled without plaintext ever landing in a Go
// string on the calling side.
type KeysClient interface {
	// Generate creates a new key and returns its metadata.
	Generate(ctx context.Context, req GenerateRequest) (*Key, error)

	// Import ingests a PEM-encoded key. When the PEM is encrypted, the
	// provider is invoked to supply a passphrase; passing a nil
	// provider with an encrypted PEM returns an error.
	Import(ctx context.Context, req ImportRequest, provider secure.PassphraseProvider) (*Key, error)

	// Get loads metadata for a single key.
	Get(ctx context.Context, req GetKeyRequest) (*Key, error)

	// List enumerates keys.
	List(ctx context.Context, req ListKeysRequest) ([]*Key, error)

	// Delete removes a key and destroys its enclave.
	Delete(ctx context.Context, req DeleteKeyRequest) error

	// ExportPublic returns the public half only.
	ExportPublic(ctx context.Context, req ExportRequest) (*PublicKey, error)

	// Signer returns an ssh.Signer backed by the key's sealed
	// material. For the embedded transport this is pkg/ssh/keys's
	// enclave-backed signer; remote transports implement a
	// forward-signing proxy that POSTs digests over the wire.
	Signer(ctx context.Context, req GetKeyRequest) (gossh.Signer, error)
}

// KnownHostsClient manages pinned host-key fingerprints.
type KnownHostsClient interface {
	Add(ctx context.Context, req AddKnownHostRequest) error
	List(ctx context.Context, req ListKnownHostsRequest) ([]*Pin, error)
	Remove(ctx context.Context, req RemoveKnownHostRequest) error

	// Verify compares a received host key against the pin store.
	Verify(ctx context.Context, scope, owner, host string, received gossh.PublicKey) error

	// Callback returns an ssh.HostKeyCallback suitable for installing
	// on an ssh.ClientConfig. The Session sub-client wires this
	// automatically; external callers may install it themselves when
	// building custom SSH flows.
	Callback(ctx context.Context, scope, owner string) gossh.HostKeyCallback
}

// AuthorizedKeysClient manages authorized_keys records and provides
// emission / parsing helpers that are transport-independent.
type AuthorizedKeysClient interface {
	Add(ctx context.Context, req AddAuthorizedKeyRequest) error
	Get(ctx context.Context, scope, owner, name string) (*AuthorizedEntry, error)
	List(ctx context.Context, req ListAuthorizedKeysRequest) ([]*AuthorizedEntry, error)
	Remove(ctx context.Context, scope, owner, name string) error

	// Emit formats a single entry as an authorized_keys line.
	Emit(ctx context.Context, req EmitRequest) (string, error)

	// Verify matches an inbound public key against the stored
	// authorized entries for (scope, owner).
	Verify(ctx context.Context, scope, owner string, received gossh.PublicKey) (*AuthorizedEntry, error)
}

// SessionClient opens outbound SSH sessions using keys + known_hosts
// the Client owns.
type SessionClient interface {
	// Dial establishes a session. The returned Session owns the
	// underlying key enclave — Session.Close destroys it.
	Dial(ctx context.Context, req SessionDialRequest) (Session, error)
}

// Session is the transport-neutral view of an established SSH
// connection. It intentionally mirrors the pkg/ssh/session.Session
// contract so the embedded transport can return its internal type
// directly; remote transports implement a thin proxy that marshals
// commands over the wire and returns byte buffers.
type Session interface {
	// Run executes a command and returns stdout, stderr, and a
	// *session.CommandError on non-zero exit.
	Run(ctx context.Context, cmd string) (stdout, stderr []byte, err error)

	// Close terminates the SSH connection and destroys any owned
	// enclaves.
	Close() error
}
