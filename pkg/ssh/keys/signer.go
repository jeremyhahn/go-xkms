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

package keys

import (
	"context"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Signer returns an ssh.Signer backed by this Key's sealed material.
// The signer does NOT keep the key's Buffer alive between Sign calls —
// every Sign() opens the Secret, parses the PEM inside a Buffer,
// constructs a transient ssh.Signer via ssh.ParsePrivateKey, delegates
// the signing operation, and destroys the Buffer before returning.
//
// This trades a small per-sign CPU cost for the guarantee that
// plaintext key material exists only during the duration of the signing
// call. For SSH workloads the parse overhead is negligible compared to
// the network round-trip; for batch-signing servers the software
// backend's signer path should be preferred (see pkg/backend/software).
//
// The PublicKey returned by the returned signer is memoized on the Key
// itself — it is public material and safe to share without re-parsing.
func (k *Key) Signer() (ssh.Signer, error) {
	if k == nil {
		return nil, &NilInputError{Field: "key"}
	}
	if k.Material == nil {
		return nil, &NilInputError{Field: "key.Material"}
	}
	if k.PublicKey == nil {
		return nil, &NilInputError{Field: "key.PublicKey"}
	}
	return &enclaveSigner{key: k}, nil
}

// SignerWithClose returns an ssh.Signer that holds the key's decrypted
// PEM inside a long-lived *secure.Buffer along with a close function
// that destroys that Buffer. The caller MUST invoke the returned close
// function exactly once when finished with the signer — typically via
// defer immediately after a non-error return.
//
// This API is intended for long-lived signer scenarios (for example the
// REST remote-signer proxy that forwards digests to xkmsd) where the
// per-Sign re-open cost of (*Key).Signer is undesirable, and where the
// session-scoped lifetime of (*Key).Destroy does not apply because the
// signer may outlive the *Key value itself.
//
// Memory discipline: the returned signer references an *open* Buffer.
// The Buffer is destroyed either when the returned close function is
// invoked or when a secure.Purge() runs (whichever comes first). The
// *Key that produced this signer may be destroyed independently — the
// signer is no longer coupled to the *Key's Material Secret.
//
// The returned closer is idempotent: the second and subsequent calls
// are no-ops and return normally.
func (k *Key) SignerWithClose() (ssh.Signer, func(), error) {
	if k == nil {
		return nil, nil, &NilInputError{Field: "key"}
	}
	if k.Material == nil {
		return nil, nil, &NilInputError{Field: "key.Material"}
	}
	if k.PublicKey == nil {
		return nil, nil, &NilInputError{Field: "key.PublicKey"}
	}

	buf, err := k.Material.Open()
	if err != nil {
		return nil, nil, &KeyMaterialError{Op: "open secret for persistent signer", Err: err}
	}
	inner, err := ssh.ParsePrivateKey(buf.Bytes())
	if err != nil {
		buf.Destroy()
		return nil, nil, &PEMParseError{Err: err}
	}

	ps := &persistentSigner{
		pub:   k.PublicKey,
		inner: inner,
		buf:   buf,
	}
	closer := func() {
		if !ps.closed.CompareAndSwap(false, true) {
			return
		}
		if ps.buf != nil {
			ps.buf.Destroy()
			ps.buf = nil
		}
		ps.inner = nil
	}
	return ps, closer, nil
}

// BackendSigner returns an ssh.Signer for a backend-backed key by resolving
// the key's crypto.Signer from the supplied BackendProvider and wrapping it
// via ssh.NewSignerFromSigner. The private key never crosses the boundary —
// for tpm2/pkcs11/cloud backends every Sign call is delegated to the device.
//
// Returns *NilInputError when the key is not backend-backed (use Signer for
// software keys) or p is nil, and *KeyMaterialError when the backend lookup
// or signer construction fails.
func (k *Key) BackendSigner(ctx context.Context, p BackendProvider) (ssh.Signer, error) {
	if k == nil {
		return nil, &NilInputError{Field: "key"}
	}
	if !k.IsBackendBacked() {
		return nil, &NilInputError{Field: "key.BackendID"}
	}
	if p == nil {
		return nil, &NilInputError{Field: "provider"}
	}
	cs, err := p.Signer(ctx, k.BackendID, k.BackendKeyID, k.Algorithm)
	if err != nil {
		return nil, &KeyMaterialError{Op: "resolve backend signer", Err: err}
	}
	sshSigner, err := ssh.NewSignerFromSigner(cs)
	if err != nil {
		return nil, &KeyMaterialError{Op: "ssh.NewSignerFromSigner", Err: err}
	}
	return sshSigner, nil
}

// enclaveSigner implements ssh.Signer by re-opening the underlying
// Secret on each Sign call. This is intentional — see the docstring on
// Key.Signer for the rationale.
type enclaveSigner struct {
	key *Key
}

// PublicKey returns the key's public half. No Secret access required.
func (s *enclaveSigner) PublicKey() ssh.PublicKey {
	return s.key.PublicKey
}

// Sign opens the Secret, parses the PEM into a transient ssh.Signer,
// delegates the signature operation, and destroys the Buffer before
// returning. The transient signer's Go-side private-key struct is not
// tracked by this package — x/crypto/ssh copies it into its own
// internal state, which is outside our control. Callers that need
// stronger guarantees should use the HSM or PKCS#11 backend.
func (s *enclaveSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	buf, err := s.key.Material.Open()
	if err != nil {
		return nil, &KeyMaterialError{Op: "open secret for sign", Err: err}
	}
	defer buf.Destroy()

	signer, err := ssh.ParsePrivateKey(buf.Bytes())
	if err != nil {
		return nil, &PEMParseError{Err: err}
	}
	return signer.Sign(rand, data)
}

// SignWithAlgorithm implements ssh.AlgorithmSigner so RSA keys can produce
// rsa-sha2-256/512 signatures instead of the legacy ssh-rsa (SHA-1), which
// modern OpenSSH servers reject. It re-opens the Secret, parses the PEM into a
// transient signer, and forwards to that signer's algorithm-aware Sign when
// available (falling back to the default algorithm otherwise).
func (s *enclaveSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	buf, err := s.key.Material.Open()
	if err != nil {
		return nil, &KeyMaterialError{Op: "open secret for sign", Err: err}
	}
	defer buf.Destroy()

	signer, err := ssh.ParsePrivateKey(buf.Bytes())
	if err != nil {
		return nil, &PEMParseError{Err: err}
	}
	if as, ok := signer.(ssh.AlgorithmSigner); ok {
		return as.SignWithAlgorithm(rand, data, algorithm)
	}
	return signer.Sign(rand, data)
}

// persistentSigner is an ssh.Signer that retains the decrypted PEM
// inside a long-lived *secure.Buffer rather than re-opening the Secret
// on every Sign call. The paired closer returned by Key.SignerWithClose
// wipes the Buffer and drops the inner signer reference.
type persistentSigner struct {
	pub    ssh.PublicKey
	inner  ssh.Signer
	buf    *secure.Buffer
	closed atomic.Bool
}

// PublicKey returns the cached public half.
func (s *persistentSigner) PublicKey() ssh.PublicKey {
	return s.pub
}

// Sign delegates to the retained inner signer. Returns *ClosedSignerError
// if the closer has already run.
func (s *persistentSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	if s.closed.Load() || s.inner == nil {
		return nil, &ClosedSignerError{}
	}
	return s.inner.Sign(rand, data)
}

// SignWithAlgorithm implements ssh.AlgorithmSigner, forwarding to the retained
// inner signer when it is algorithm-aware (enabling rsa-sha2-256/512 for RSA
// keys). Returns *ClosedSignerError if the closer has already run.
func (s *persistentSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if s.closed.Load() || s.inner == nil {
		return nil, &ClosedSignerError{}
	}
	if as, ok := s.inner.(ssh.AlgorithmSigner); ok {
		return as.SignWithAlgorithm(rand, data, algorithm)
	}
	return s.inner.Sign(rand, data)
}
