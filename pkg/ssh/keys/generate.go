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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// GenerateOptions tunes key generation. Callers construct this
// explicitly (no functional-options / variadic soup) because the
// attribute set is small, finite, and entirely algorithm-dependent.
type GenerateOptions struct {
	// Algorithm selects the public-key cryptosystem. Required.
	Algorithm Algorithm

	// RSABits is the modulus size for AlgorithmRSA. Ignored for other
	// algorithms. Defaults to 4096 when zero. Enforced range:
	// [types.RSAKeySize2048, types.RSAKeySize4096] -- the ceiling exists
	// because rsa.GenerateKey cannot be cancelled and its cost grows with
	// the cube of the modulus size (go-xkms#1260).
	RSABits int

	// Comment is written into the OpenSSH PEM block (appears in
	// authorized_keys / fingerprint output). Safe to leave empty.
	Comment string
}

// Generate creates a new SSH key of the specified algorithm. The
// private key material is sealed into a *secure.Secret in OpenSSH PEM
// form; the raw []byte produced by ssh.MarshalPrivateKey is wiped
// before Generate returns. Metadata fields (Scope, Owner, Name,
// Comment) are copied from opts; CreatedAt is set to time.Now().
//
// Returns:
//   - *UnsupportedAlgorithmError if opts.Algorithm is unrecognized.
//   - *InvalidKeySizeError if RSABits is outside the supported range.
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
		// types.ValidateRSAKeySize enforces both the NIST-required floor and
		// the go-xkms#1260 ceiling: rsa.GenerateKey cannot be cancelled and
		// its cost grows with the cube of the modulus size, so an unbounded
		// caller-chosen bits would let one request pin a CPU core for
		// minutes to hours.
		if err := types.ValidateRSAKeySize(bits); err != nil {
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

// GenerateOnBackend creates a backend-backed SSH key: the private half is
// generated and held by the crypto backend identified by backendID (via p),
// and only the public key plus a backend reference are returned. The
// resulting Key carries nil Material — signing is delegated through
// (*Key).BackendSigner. This is the hardware-backed counterpart to Generate:
// for tpm2/pkcs11/cloud backends the private key never leaves the device.
//
// Returns:
//   - *NilInputError if p is nil or backendID is empty.
//   - *UnsupportedAlgorithmError if opts.Algorithm is empty or unrecognized.
//   - *InvalidKeySizeError if RSABits is non-zero and outside the supported range.
//   - *KeyMaterialError if the backend or public-key derivation fails.
func GenerateOnBackend(ctx context.Context, p BackendProvider, backendID string, opts GenerateOptions, sc scope.Scope, owner, name string) (*Key, error) {
	if p == nil {
		return nil, &NilInputError{Field: "provider"}
	}
	if backendID == "" {
		return nil, &NilInputError{Field: "backendID"}
	}
	if opts.Algorithm == "" {
		return nil, &UnsupportedAlgorithmError{Algorithm: "<empty>"}
	}
	if !opts.Algorithm.supported() {
		return nil, &UnsupportedAlgorithmError{Algorithm: string(opts.Algorithm)}
	}
	// Refused here, before the backend is ever asked to generate a key, for
	// the same go-xkms#1260 reason Generate refuses it: an unbounded
	// caller-chosen size can pin a CPU core for minutes to hours, and a
	// backend is not guaranteed to enforce the ceiling itself.
	if opts.Algorithm == AlgorithmRSA && opts.RSABits != 0 {
		if err := types.ValidateRSAKeySize(opts.RSABits); err != nil {
			return nil, &InvalidKeySizeError{Algorithm: "rsa", Size: opts.RSABits}
		}
	}

	keyID, err := backendKeyID(sc, owner, name)
	if err != nil {
		return nil, err
	}

	signer, err := p.GenerateKey(ctx, backendID, keyID, opts.Algorithm, opts.RSABits)
	if err != nil {
		return nil, &KeyMaterialError{Op: "backend GenerateKey", Err: err}
	}
	if signer == nil {
		return nil, &KeyMaterialError{Op: "backend GenerateKey", Err: &NilInputError{Field: "backend signer"}}
	}
	pub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return nil, &KeyMaterialError{Op: "ssh.NewPublicKey", Err: err}
	}

	return &Key{
		PublicKey:    pub,
		Algorithm:    opts.Algorithm,
		Fingerprint:  Fingerprint(pub),
		Scope:        sc,
		Owner:        owner,
		Name:         name,
		CreatedAt:    time.Now().UTC(),
		Comment:      opts.Comment,
		BackendID:    backendID,
		BackendKeyID: keyID,
	}, nil
}

// maxBackendKeyIDLen bounds the CN backendKeyID produces. 255 matches
// pkg/validation.ValidateKeyID's own limit on every other xkms key
// identifier, and stays inside NAME_MAX on every filesystem the software and
// tpm2 backends' file-per-key storage (pkg/storage.KeyPath,
// pkg/tpm2/store.storageKey) is deployed on.
const maxBackendKeyIDLen = 255

// backendKeyID derives a stable, backend-safe CN for a backend-backed SSH
// key from its (scope, owner, name) identity.
//
// scope.BuildKeyID is called first purely for its validation (non-empty
// owner/name, a valid scope, no embedded '/') so callers keep seeing the
// same *scope.ScopeInvalidError / *scope.KeyIDMalformedError they saw
// before; its "<scope>/<owner>/<name>" result is discarded, because
// flattening that joined string by replacing '/' with '-' is not injective
// when owner or name already contains a '-': "user/a-b/c" and "user/a/b-c"
// both flattened to "ssh-user-a-b-c" (go-xkms#1238), letting one tenant's
// key silently address, and overwrite, another key's backend CN.
//
// Instead, owner and name are hex-encoded independently and joined with
// '-'. hex.EncodeToString only ever emits [0-9a-f], so a '-' in the result
// can only be one of the three separators this function writes literally —
// it can never occur inside a hex-encoded segment — making the join
// unambiguous (and therefore injective in (scope, owner, name)) regardless
// of what bytes owner or name contain. This also keeps the CN within the
// character set every backend's identifier format requires: colon-free (the
// unified xkms key ID format in types.KeyAttributes.ID reserves ':' as its
// own separator) and '/'-free (the software and tpm2 backends use the CN
// directly as a storage key — see pkg/storage.KeyPath and
// pkg/tpm2/store.storageKey — where an embedded '/' would nest a path
// instead of naming one key).
//
// Returns *BackendKeyIDTooLongError instead of silently truncating or
// letting an oversized CN fail deep inside a backend when owner and name
// together push the encoded CN past maxBackendKeyIDLen.
func backendKeyID(sc scope.Scope, owner, name string) (string, error) {
	if _, err := scope.BuildKeyID(sc, owner, name); err != nil {
		return "", err
	}
	n := len("ssh--") + len(sc) + 1 + hex.EncodedLen(len(owner)) + hex.EncodedLen(len(name))
	if n > maxBackendKeyIDLen {
		return "", &BackendKeyIDTooLongError{Length: n, Max: maxBackendKeyIDLen}
	}
	var b strings.Builder
	b.Grow(n)
	b.WriteString("ssh-")
	b.WriteString(string(sc))
	b.WriteByte('-')
	b.WriteString(hex.EncodeToString([]byte(owner)))
	b.WriteByte('-')
	b.WriteString(hex.EncodeToString([]byte(name)))
	return b.String(), nil
}
