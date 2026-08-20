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
	"sync"
	"time"

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

// SignWithFlags signs data, honoring rsa-sha2 upgrade flags.
//
// An RSA key never signs with SHA-1 here. x/crypto's default for an RSA signer
// is the legacy ssh-rsa algorithm, which modern servers reject and which is not
// an approved primitive under the project's FIPS 140-3 requirement -- and since
// this agent is reachable by any ssh-agent client, an unflagged request is the
// client's default, not a deliberate choice. So an RSA request with no rsa-sha2
// flag is signed with rsa-sha2-256 rather than falling through, and an RSA
// signer that cannot select an algorithm at all is refused outright instead of
// silently producing SHA-1.
func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	signer := a.signerFor(key)
	if signer == nil {
		return nil, &UnknownKeyError{Format: key.Type()}
	}
	as, canSelect := signer.(ssh.AlgorithmSigner)
	if isRSA(signer.PublicKey()) {
		if !canSelect {
			return nil, &UnsupportedAlgorithmError{Algorithm: signer.PublicKey().Type()}
		}
		algo := ssh.KeyAlgoRSASHA256
		if flags&sshagent.SignatureFlagRsaSha512 != 0 {
			algo = ssh.KeyAlgoRSASHA512
		}
		return as.SignWithAlgorithm(rand.Reader, data, algo)
	}
	// Non-RSA keys carry their algorithm in the key type; the rsa-sha2 flags
	// are meaningless for them.
	return signer.Sign(rand.Reader, data)
}

// isRSA reports whether a public key is an RSA key in any of its spellings
// (ssh-rsa and the rsa-sha2-* certificate/algorithm variants).
func isRSA(pub ssh.PublicKey) bool {
	switch pub.Type() {
	case ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.CertAlgoRSAv01,
		ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01:
		return true
	}
	return false
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

// handlerJoinTimeout bounds how long shutdown waits for connection handlers to
// notice their closed connections. It is generous for the ordinary case (a
// handler blocked on a read returns at once) and finite for the pathological
// one (a handler blocked inside an uninterruptible Sign).
const handlerJoinTimeout = 5 * time.Second

// joinWithin waits for wg, giving up after d. The watcher goroutine ends when
// the last handler finishes, however long that takes.
func joinWithin(wg *sync.WaitGroup, d time.Duration) {
	joined := make(chan struct{})
	go func() {
		wg.Wait()
		close(joined)
	}()
	select {
	case <-joined:
	case <-time.After(d):
	}
}

// occupancyProbeTimeout bounds the dial that decides which error an occupied
// socket path deserves. Connecting to a unix socket with a listener behind it
// is immediate; anything slower is an unresponsive owner, not an absent one.
const occupancyProbeTimeout = 2 * time.Second

// listen binds the agent socket at socketPath, creating its parent directory.
// The socket is created with 0600 permissions.
//
// **Unexported deliberately.** net.Listen binds first and the mode is applied
// after, so between those two steps the socket carries whatever the process
// umask left it. Nothing in Go closes that window for an arbitrary path, and
// tightening the mode afterwards does not disconnect a client that connected
// during it. What does close it is the *directory*: in a 0700 directory nobody
// else can traverse in to reach the socket, whatever its mode is meanwhile.
//
// So this is reachable only through StartSession, which binds in a directory
// that is private by construction — one it created itself, or one it has
// checked. A raw exported binder taking any path would be an invitation to
// bind in a shared directory, where the window is real.
//
// **Nothing at socketPath is ever removed.** An occupied path is refused:
// ErrSocketInUse when an agent answers there, ErrPathOccupied otherwise.
// Clearing a leftover looks helpful and cannot be done safely — inspect, unlink
// and bind are three steps, and between them another process can bind its own
// live agent at that path, which the unlink would then destroy, redirecting its
// children onto a different key set. Refusing costs an error a caller can act
// on; guessing costs someone else's key isolation. A leftover from a crashed
// run therefore belongs to whoever owns the directory.
func listen(socketPath string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return nil, &ListenError{Err: err}
	}
	// Refuse an occupied path; never clear one. The probe only chooses which
	// error the caller gets -- nothing here mutates the filesystem, so there is
	// no inspect-then-act window for another process to slip through.
	if info, lerr := os.Lstat(socketPath); lerr == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, &ListenError{Err: ErrPathOccupied}
		}
		if c, derr := net.DialTimeout("unix", socketPath, occupancyProbeTimeout); derr == nil {
			_ = c.Close()
			return nil, &ListenError{Err: ErrSocketInUse}
		}
		// A socket nobody answers is a leftover, and it is the directory
		// owner's to remove -- see the note on this function.
		return nil, &ListenError{Err: ErrPathOccupied}
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, &ListenError{Err: err}
	}
	if cerr := os.Chmod(socketPath, 0o600); cerr != nil {
		_ = ln.Close()
		return nil, &ListenError{Err: cerr}
	}
	return ln, nil
}

// serveListener serves a to every connection accepted on ln until ctx is
// cancelled, then closes ln and disconnects every client still attached. It
// blocks; run it in a goroutine and cancel ctx to stop. Graceful shutdown
// returns nil. Unexported for the same reason as listen: the pair is only safe
// together with a directory StartSession vouches for.
//
// Shutdown is complete when ServeListener returns: closing the listener alone
// would leave already-accepted clients able to go on issuing sign requests
// through a session its owner believes is over, which is a signing oracle
// nobody is watching. Live connections are closed and their handlers joined.
//
// The socket file is removed by closing ln, which unlinks the path it bound,
// and nothing here unlinks it a second time. A later removal would be a
// removal of whatever holds the path *by then* -- and joining slow handlers
// takes long enough for a successor session on the same WorkDir to have bound
// it, whose live socket we would then delete.
func serveListener(ctx context.Context, ln net.Listener, a sshagent.Agent) error {
	var (
		mu       sync.Mutex
		live     = make(map[net.Conn]struct{})
		draining bool
		handlers sync.WaitGroup
	)
	// drain disconnects every attached client and refuses any further one.
	drain := func() {
		mu.Lock()
		defer mu.Unlock()
		draining = true
		for c := range live {
			_ = c.Close()
		}
	}

	// returned stops the ctx watcher when ServeListener exits for its own
	// reasons, so the goroutine does not outlive the call on an accept error.
	returned := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
			drain()
		case <-returned:
		}
	}()
	defer func() {
		close(returned)
		// Closing the listener unlinks the socket; drain disconnects everyone
		// already attached. Together those are what make the session unusable,
		// and both are unconditional.
		_ = ln.Close()
		drain()
		// Joining the handlers afterwards is hygiene, not security, so it is
		// bounded. A handler stuck inside Signer.Sign -- a TPM awaiting touch,
		// a stalled KMS -- cannot be interrupted by closing its connection, but
		// it also cannot answer anyone: the connection it would write the
		// signature to is already closed above. Waiting on it forever would
		// hang Stop and leave the work directory unreaped to protect against an
		// oracle that no longer has anybody to talk to.
		joinWithin(&handlers, handlerJoinTimeout)
	}()

	for {
		conn, aerr := ln.Accept()
		if aerr != nil {
			if ctx.Err() != nil {
				return nil // graceful shutdown
			}
			return &AcceptError{Err: aerr}
		}

		mu.Lock()
		if draining {
			// Accepted in the window between cancellation and the listener
			// closing; it must not be served.
			mu.Unlock()
			_ = conn.Close()
			continue
		}
		live[conn] = struct{}{}
		// Add under the same lock drain takes. Outside it, shutdown could set
		// draining, see an empty handler set and reach Wait between the unlock
		// and the Add -- which is both a WaitGroup misuse panic and a session
		// reporting itself stopped while this handler was still answering.
		handlers.Add(1)
		mu.Unlock()

		go func(c net.Conn) {
			defer handlers.Done()
			defer func() {
				mu.Lock()
				delete(live, c)
				mu.Unlock()
				_ = c.Close()
			}()
			_ = sshagent.ServeAgent(a, c)
		}(conn)
	}
}

// Serve listens on socketPath and serves a to every connection until ctx is
// cancelled. The socket is created with 0600 permissions and removed on return.
// Serve blocks; run it in a goroutine and cancel ctx to stop.
//
// The socket's parent directory must be private to this user, on the same terms
// StartSession applies: an agent socket in a directory others can traverse is
// reachable during the window between bind and chmod, and its pathname can be
// replaced outright. Prefer StartSession, which owns a private directory rather
// than requiring the caller to supply one.
func Serve(ctx context.Context, socketPath string, a sshagent.Agent) error {
	if err := checkWorkDir(filepath.Dir(socketPath)); err != nil {
		return err
	}
	ln, err := listen(socketPath)
	if err != nil {
		return err
	}
	return serveListener(ctx, ln, a)
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
