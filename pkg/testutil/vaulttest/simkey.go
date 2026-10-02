// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package vaulttest

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"

	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// SimulatedKey simulates a PIN-protected FIDO2 security key's hmac-secret
// extension for the vault passkey tests of every surface (it satisfies
// vaultpasskey.Authenticator). Each credential has a secret that never
// leaves the key; an evaluation returns HMAC-SHA-256(secret, salt) for the
// salt the key RECEIVES, so a test that reproduces an output has proved
// which salt reached the key. A missing PIN answers fido2.ErrPINRequired, a
// wrong PIN fido2.ErrInvalidPIN, and a credential the key does not hold for
// the requested RP fido2.ErrCredentialNotFound, exactly as the CTAP layer
// reports them.
type SimulatedKey struct {
	// PIN is the key's client PIN, sealed in protected memory. Nil means the
	// key has no PIN configured.
	PIN *secure.Secret

	// Received records every hmac-secret salt the key evaluated, in order.
	Received [][]byte

	// Closed reports whether Close was called; CloseErr is what it returns.
	Closed   bool
	CloseErr error

	credentials map[string][]byte // rpID + "/" + credential ID -> secret
}

// NewSimulatedKey returns a key whose PIN is pin. An empty pin leaves the
// key with no PIN configured.
func NewSimulatedKey(pin string) *SimulatedKey {
	k := &SimulatedKey{credentials: map[string][]byte{}}
	if pin == "" {
		return k
	}
	sealed, err := secure.NewSecret([]byte(pin))
	if err != nil {
		// NewSecret only fails on a non-positive size, which pin != ""
		// already rules out: a test fixture construction bug, not a
		// runtime condition callers can recover from.
		panic(err)
	}
	k.PIN = sealed
	return k
}

func (k *SimulatedKey) checkPIN(pin *secure.Secret) error {
	if pin == nil {
		return fido2.ErrPINRequired
	}
	if k.PIN == nil {
		return fido2.ErrInvalidPIN
	}
	buf, err := pin.Open()
	if err != nil {
		return err
	}
	defer buf.Destroy()
	// The candidate is copied out and wiped rather than nesting two
	// borrows; the stored PIN is compared inside its own borrow.
	candidate, err := secure.CopyOut(buf)
	if err != nil {
		return err
	}
	defer secure.Wipe(candidate)
	kbuf, err := k.PIN.Open()
	if err != nil {
		return err
	}
	defer kbuf.Destroy()
	return kbuf.WithBytes(func(stored []byte) error {
		if !bytes.Equal(candidate, stored) {
			return fido2.ErrInvalidPIN
		}
		return nil
	})
}

// EnrollKey creates a credential for cfg's relying party.
func (k *SimulatedKey) EnrollKey(cfg *fido2.EnrollmentConfig) (*fido2.EnrollmentResult, error) {
	if err := k.checkPIN(cfg.PIN); err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	secret := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	k.credentials[cfg.RelyingParty.ID+"/"+string(id)] = secret
	return &fido2.EnrollmentResult{CredentialID: id, RelyingParty: cfg.RelyingParty}, nil
}

// Seed installs a credential with a known per-credential secret (the CTAP2
// CredRandomWithUV), so a test can check outputs against fixed vectors.
func (k *SimulatedKey) Seed(rpID string, credentialID, credRandom []byte) {
	k.credentials[rpID+"/"+string(credentialID)] = bytes.Clone(credRandom)
}

// DeriveHMACSecret evaluates the credential's hmac-secret over cfg.Salt.
func (k *SimulatedKey) DeriveHMACSecret(cfg *fido2.AuthenticationConfig) (*fido2.AuthenticationResult, error) {
	if err := k.checkPIN(cfg.PIN); err != nil {
		return nil, err
	}
	secret, ok := k.credentials[cfg.RelyingPartyID+"/"+string(cfg.CredentialID)]
	if !ok {
		return nil, fido2.ErrCredentialNotFound
	}
	k.Received = append(k.Received, bytes.Clone(cfg.Salt))
	return &fido2.AuthenticationResult{HMACSecret: hmacOver(secret, cfg.Salt)}, nil
}

// Close records the close and returns CloseErr.
func (k *SimulatedKey) Close() error {
	k.Closed = true
	return k.CloseErr
}

// Evaluate returns the credential's hmac-secret over salt exactly, with no
// transform: what a client that skipped the WebAuthn prf transform would
// send. ok is false for a credential the key does not hold.
func (k *SimulatedKey) Evaluate(rpID string, credentialID, salt []byte) (output []byte, ok bool) {
	secret, ok := k.credentials[rpID+"/"+string(credentialID)]
	if !ok {
		return nil, false
	}
	return hmacOver(secret, salt), true
}

// BrowserPRF returns what a browser's WebAuthn prf evaluation with
// eval.first = first yields for the credential: the hmac-secret over
// SHA-256("WebAuthn PRF" || 0x00 || first), written from the WebAuthn
// definition rather than with fido2.WebAuthnPRFSalt.
func (k *SimulatedKey) BrowserPRF(rpID string, credentialID, first []byte) (output []byte, ok bool) {
	salt := sha256.Sum256(append([]byte("WebAuthn PRF\x00"), first...))
	return k.Evaluate(rpID, credentialID, salt[:])
}

func hmacOver(secret, salt []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(salt)
	return mac.Sum(nil)
}
