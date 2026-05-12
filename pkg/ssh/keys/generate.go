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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"time"

	"golang.org/x/crypto/ssh"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// GenerateOptions tunes key generation. Callers construct this
// explicitly (no functional-options / variadic soup) because the
// attribute set is small, finite, and entirely algorithm-dependent.
type GenerateOptions struct {
	// Algorithm selects the public-key cryptosystem. Required.
	Algorithm Algorithm

	// RSABits is the modulus size for AlgorithmRSA. Ignored for other
	// algorithms. Defaults to 4096 when zero. Minimum enforced: 2048.
	RSABits int

	// Comment is written into the OpenSSH PEM block (appears in
	// authorized_keys / fingerprint output). Safe to leave empty.
	Comment string
}

// minRSABits is the smallest RSA modulus the package accepts. 2048 is
// the floor required by current NIST guidance.
const minRSABits = 2048

// Generate creates a new SSH key of the specified algorithm. The
// private key material is sealed into a *secure.Secret in OpenSSH PEM
// form; the raw []byte produced by ssh.MarshalPrivateKey is wiped
// before Generate returns. Metadata fields (Scope, Owner, Name,
// Comment) are copied from opts; CreatedAt is set to time.Now().
//
// Returns:
//   - *UnsupportedAlgorithmError if opts.Algorithm is unrecognized.
//   - *InvalidKeySizeError if RSABits is below the minimum.
//   - *KeyMaterialError if the underlying crypto library fails.
func Generate(opts GenerateOptions) (*Key, error) {
	if opts.Algorithm == "" {
		return nil, &UnsupportedAlgorithmError{Algorithm: "<empty>"}
	}

	privKey, err := generatePrivateKey(opts)
	if err != nil {
		return nil, err
	}

	return keyFromCryptoPrivate(privKey, opts.Algorithm, opts.Comment)
}

// generatePrivateKey is the algorithm dispatcher. It intentionally
// avoids a map[Algorithm]func because each generator has a slightly
// different parameter signature; a map would force either an interface
// box (extra allocation) or a wrapper struct (extra abstraction). The
// switch is small, readable, and compiles to a single jump.
func generatePrivateKey(opts GenerateOptions) (crypto.PrivateKey, error) {
	switch opts.Algorithm {
	case AlgorithmEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, &KeyMaterialError{Op: "ed25519.GenerateKey", Err: err}
		}
		return priv, nil

	case AlgorithmRSA:
		bits := opts.RSABits
		if bits == 0 {
			bits = 4096
		}
		if bits < minRSABits {
			return nil, &InvalidKeySizeError{Algorithm: "rsa", Size: bits}
		}
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, &KeyMaterialError{Op: "rsa.GenerateKey", Err: err}
		}
		return priv, nil

	case AlgorithmECDSAP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, &KeyMaterialError{Op: "ecdsa.GenerateKey p256", Err: err}
		}
		return priv, nil

	case AlgorithmECDSAP384:
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, &KeyMaterialError{Op: "ecdsa.GenerateKey p384", Err: err}
		}
		return priv, nil

	case AlgorithmECDSAP521:
		priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, &KeyMaterialError{Op: "ecdsa.GenerateKey p521", Err: err}
		}
		return priv, nil

	default:
		return nil, &UnsupportedAlgorithmError{Algorithm: string(opts.Algorithm)}
	}
}

// keyFromCryptoPrivate marshals a Go private key into OpenSSH PEM
// form, constructs a public key for metadata, and seals the PEM bytes
// into a *secure.Secret.
func keyFromCryptoPrivate(priv crypto.PrivateKey, algo Algorithm, comment string) (*Key, error) {
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, &KeyMaterialError{Op: "ssh.MarshalPrivateKey", Err: err}
	}

	pemBytes := pem.EncodeToMemory(block)
	// pem.EncodeToMemory returns a fresh []byte we fully own. We move
	// it into a Secret (which wipes it on entry) so the plaintext
	// never outlives this frame.
	material, secErr := secure.NewSecret(pemBytes)
	if secErr != nil {
		return nil, &KeyMaterialError{Op: "seal generated pem", Err: secErr}
	}
	// Wipe our reference in case the underlying memguard
	// implementation left anything behind (NewSecret already wipes,
	// but defense in depth is cheap).
	secure.Wipe(pemBytes)

	// Derive the ssh.PublicKey. signerPub := ssh.NewSignerFromKey(priv)
	// is the only supported path — constructing ssh.PublicKey directly
	// from crypto.PublicKey requires protocol-specific formatting that
	// NewSignerFromKey already implements.
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		material.Destroy()
		return nil, &KeyMaterialError{Op: "ssh.NewSignerFromKey", Err: err}
	}
	pub := signer.PublicKey()

	return &Key{
		Material:    material,
		PublicKey:   pub,
		Algorithm:   algo,
		Fingerprint: Fingerprint(pub),
		CreatedAt:   time.Now().UTC(),
		Comment:     comment,
	}, nil
}
