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

// Package agent provides a read-only SSH agent that serves a fixed set of
// signers over the SSH agent protocol (SSH_AUTH_SOCK). It lets the system ssh
// client authenticate with an xkey-managed key — including a hardware-backed
// key whose private half never leaves the device, because only the
// crypto-backed ssh.Signer is exposed (never key material). It is distinct from
// xkey/pkg/agent (the master↔child IPC forwarder).
package agent

import (
	"context"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// Agent is a read-only ssh-agent that serves a fixed set of signers. Add /
// Remove / Lock are unsupported — identities are provisioned at construction.
type Agent struct {
	signers []ssh.Signer
}

// compile-time assertion that Agent satisfies the extended agent interface
// (so SignWithFlags is used for rsa-sha2 requests).
var _ sshagent.ExtendedAgent = (*Agent)(nil)

// New constructs an Agent serving the given signers (the chosen key's
// ssh.Signer, typically from the SSH SDK Client.Signer).
func New(signers ...ssh.Signer) *Agent {
	return &Agent{signers: signers}
}

// List returns the public keys of the served signers.
func (a *Agent) List() ([]*sshagent.Key, error) {
	keys := make([]*sshagent.Key, 0, len(a.signers))
	for i, s := range a.signers {
		pub := s.PublicKey()
		keys = append(keys, &sshagent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: "xkey-" + itoa(i),
		})
	}
	return keys, nil
}

// Signers returns the served signers.
func (a *Agent) Signers() ([]ssh.Signer, error) {
	return a.signers, nil
}

// Sign signs data with the signer matching key (default algorithm).
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

// SignWithFlags signs data, honoring rsa-sha2 upgrade flags so RSA keys produce
// rsa-sha2-256/512 signatures (modern servers reject the legacy SHA-1 ssh-rsa).
func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	signer := a.signerFor(key)
	if signer == nil {
		return nil, &UnknownKeyError{Format: key.Type()}
	}
	algo := ""
	if as, ok := signer.(ssh.AlgorithmSigner); ok {
		switch {
		case flags&sshagent.SignatureFlagRsaSha512 != 0:
			algo = ssh.KeyAlgoRSASHA512
		case flags&sshagent.SignatureFlagRsaSha256 != 0:
			algo = ssh.KeyAlgoRSASHA256
		}
		if algo != "" {
			return as.SignWithAlgorithm(rand.Reader, data, algo)
		}
	}
	return signer.Sign(rand.Reader, data)
}

// Extension is unsupported.
func (a *Agent) Extension(_ string, _ []byte) ([]byte, error) {
	return nil, sshagent.ErrExtensionUnsupported
}

// Add is unsupported (read-only agent).
func (a *Agent) Add(_ sshagent.AddedKey) error { return ErrUnsupported }

// Remove is unsupported (read-only agent).
func (a *Agent) Remove(_ ssh.PublicKey) error { return ErrUnsupported }

// RemoveAll is unsupported (read-only agent).
func (a *Agent) RemoveAll() error { return ErrUnsupported }

// Lock is unsupported (read-only agent).
func (a *Agent) Lock(_ []byte) error { return ErrUnsupported }

// Unlock is unsupported (read-only agent).
func (a *Agent) Unlock(_ []byte) error { return ErrUnsupported }

// signerFor returns the signer whose public key matches key, or nil.
func (a *Agent) signerFor(key ssh.PublicKey) ssh.Signer {
	want := key.Marshal()
	for _, s := range a.signers {
		if bytesEqual(s.PublicKey().Marshal(), want) {
			return s
		}
	}
	return nil
}

// Serve listens on socketPath and serves a to every connection until ctx is
// cancelled. The socket is created with 0600 permissions and removed on return.
// Serve blocks; run it in a goroutine and cancel ctx to stop.
func Serve(ctx context.Context, socketPath string, a sshagent.Agent) error {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return &ListenError{Err: err}
	}
	// Remove a stale socket from a previous run.
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return &ListenError{Err: err}
	}
	if cerr := os.Chmod(socketPath, 0o600); cerr != nil {
		_ = ln.Close()
		return &ListenError{Err: cerr}
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	defer func() {
		_ = ln.Close()
		_ = os.Remove(socketPath)
	}()

	for {
		conn, aerr := ln.Accept()
		if aerr != nil {
			if ctx.Err() != nil {
				return nil // graceful shutdown
			}
			return &AcceptError{Err: aerr}
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = sshagent.ServeAgent(a, c)
		}(conn)
	}
}

// bytesEqual reports whether two byte slices are equal.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// itoa is a tiny non-allocating-ish int→string for comment labels.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
