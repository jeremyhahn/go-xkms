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

package xkms

import (
	"context"
	"crypto"
	"errors"
	"io"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// ErrPIVCryptoSignerPublicKeyRequired is returned when a PIVCryptoSigner is
// constructed without a public key. The public key must match the slot's
// certificate exactly, or a TLS peer will reject the resulting handshake
// once it verifies the signature against the certificate it was presented.
var ErrPIVCryptoSignerPublicKeyRequired = errors.New("xkms: PIVCryptoSigner requires the slot's public key")

// pivHashAlgorithmNames maps crypto.Hash to the hash-algorithm name SignPIV
// expects. Provides O(1) constant-time lookup.
var pivHashAlgorithmNames = map[crypto.Hash]string{
	crypto.SHA256: "sha256",
	crypto.SHA384: "sha384",
	crypto.SHA512: "sha512",
}

// PIVCryptoSigner adapts a PIV slot's private key to crypto.Signer by
// delegating every signing operation to SignPIV. No key material ever
// crosses this type's boundary — the slot's key stays wherever the named
// backend keeps it (an in-process software key, a PKCS#11 token session, or
// a TPM2 handle) and only the resulting signature is returned.
//
// This is the composition point for using a PIV slot as a TLS client
// certificate's private key (tls.Certificate.PrivateKey), e.g. for PIV
// login: the slot certificate plus a PIVCryptoSigner over the same slot
// form a complete tls.Certificate.
type PIVCryptoSigner struct {
	// Backend identifies the xkms PIV backend that resolves the slot's key
	// (e.g. "software", "tpm2", "pkcs11"). It must match the backend the
	// slot's certificate was stored under.
	Backend string

	// Slot is the PIV slot identifier (e.g. "9a").
	Slot string

	// Pub is the slot's public key, read from its stored certificate. It
	// must match the certificate presented alongside this signer.
	Pub crypto.PublicKey

	// PIN optionally authenticates a PIN-gated backend. Ignored by
	// backends that authenticate the session out of band (software, or a
	// PKCS#11 token already logged in). A nil PIN means none was supplied.
	PIN *secure.Secret
}

// NewPIVCryptoSigner constructs a PIVCryptoSigner for the given backend and
// slot. pub is the slot's public key, normally read from its stored
// certificate (cert.PublicKey).
func NewPIVCryptoSigner(backend string, slot PIVSlot, pub crypto.PublicKey) (*PIVCryptoSigner, error) {
	if pub == nil {
		return nil, ErrPIVCryptoSignerPublicKeyRequired
	}
	return &PIVCryptoSigner{
		Backend: backend,
		Slot:    string(slot),
		Pub:     pub,
	}, nil
}

// Public returns the slot's public key.
func (s *PIVCryptoSigner) Public() crypto.PublicKey {
	return s.Pub
}

// Sign signs digest with the PIV slot's private key via SignPIV. rand is
// ignored: the slot's backend supplies its own randomness (or none, for
// deterministic ECDSA/hardware signers).
//
// digest is treated as an already-hashed digest for every key type except
// Ed25519, which SignPIV always signs over the raw message regardless of
// the Hashed flag, matching crypto.Signer's Ed25519 convention where the
// "digest" IS the message.
func (s *PIVCryptoSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	req := &PIVSignRequest{
		Backend:       s.Backend,
		Slot:          s.Slot,
		Payload:       digest,
		Hashed:        true,
		HashAlgorithm: pivHashAlgorithmName(opts),
	}
	if s.PIN != nil {
		buf, err := s.PIN.Open()
		if err != nil {
			return nil, err
		}
		// PIVSignRequest crosses the wire to the backend over the SDK's
		// transport (REST/gRPC/QUIC/MCP), so it carries the PIN as a plain
		// string -- the unavoidable copy at that transport-serialization
		// boundary.
		req.PIN = string(buf.Bytes())
		buf.Destroy()
	}
	resp, err := SignPIV(context.Background(), req)
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

// pivHashAlgorithmName maps opts to the hash-algorithm name SignPIV expects.
// An unrecognized or zero hash (Ed25519's crypto.Hash(0)) maps to the empty
// string, which SignPIV ignores for Ed25519 signers and otherwise resolves
// to a default derived from the key type.
func pivHashAlgorithmName(opts crypto.SignerOpts) string {
	if opts == nil {
		return ""
	}
	return pivHashAlgorithmNames[opts.HashFunc()]
}
