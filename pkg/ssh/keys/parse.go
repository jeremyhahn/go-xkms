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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// ParsePEM is the ONLY supported entry point for turning a PEM-encoded
// SSH private key into a *Key. It handles both unencrypted and
// passphrase-encrypted inputs:
//
//  1. The PEM bytes are read from pem (a secure.Buffer the caller
//     constructed and will destroy when this function returns).
//  2. ssh.ParsePrivateKey is attempted first. If it succeeds, we have
//     an unencrypted key and construction continues.
//  3. If ssh.ParsePrivateKey returns *ssh.PassphraseMissingError and
//     provider is non-nil, we request a passphrase Buffer from
//     provider and call ssh.ParsePrivateKeyWithPassphrase. The
//     passphrase Buffer is destroyed immediately after the call.
//  4. The returned Key owns a *secure.Secret holding the ORIGINAL PEM
//     bytes (not the parsed Go key). Sign, public-key derivation, and
//     any other post-parse operation re-parse from the Secret inside a
//     single stack frame, so parsed key material never outlives a
//     request.
//
// Passing a nil provider when the PEM is encrypted returns a
// *PassphraseRequiredError. Any x/crypto/ssh parse failure is wrapped
// in *PEMParseError.
func ParsePEM(ctx context.Context, pemBuf *secure.Buffer, provider secure.PassphraseProvider) (*Key, error) {
	if pemBuf == nil {
		return nil, &NilInputError{Field: "pem"}
	}
	// CopyOut refuses a nil, destroyed or empty buffer, all of which are
	// an absent PEM to the caller.
	pemBytes, err := secure.CopyOut(pemBuf)
	if err != nil {
		return nil, &NilInputError{Field: "pem"}
	}
	defer secure.Wipe(pemBytes)

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if !errors.As(err, &missing) {
			return nil, &PEMParseError{Err: err}
		}
		if provider == nil {
			return nil, &PassphraseRequiredError{}
		}
		signer, err = parseWithPassphrase(ctx, pemBytes, provider)
		if err != nil {
			return nil, err
		}
	}

	// Seal the PEM bytes into a Secret so the only long-lived copy of
	// the private key material lives inside an enclave. NewSecret wipes
	// its source slice and we must not disturb the caller's Buffer (the
	// caller will Destroy it themselves), so seal a fresh copy of it.
	sealed, copyErr := secure.CopyOut(pemBuf)
	if copyErr != nil {
		return nil, &KeyMaterialError{Op: "copy pem", Err: copyErr}
	}
	material, secErr := secure.NewSecret(sealed)
	if secErr != nil {
		return nil, &KeyMaterialError{Op: "seal pem", Err: secErr}
	}

	pub := signer.PublicKey()
	algo, algoErr := AlgorithmFromPublicKey(pub)
	if algoErr != nil {
		material.Destroy()
		return nil, algoErr
	}

	return &Key{
		Material:    material,
		PublicKey:   pub,
		Algorithm:   algo,
		Fingerprint: Fingerprint(pub),
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// parseWithPassphrase prompts the provider, parses, and destroys the
// passphrase Buffer before returning — independent of success.
func parseWithPassphrase(ctx context.Context, pemBytes []byte, provider secure.PassphraseProvider) (ssh.Signer, error) {
	pwBuf, err := provider.Passphrase(ctx, "SSH key passphrase: ")
	if err != nil {
		return nil, &PEMParseError{Err: err}
	}
	defer pwBuf.Destroy()

	passphrase, err := secure.CopyOut(pwBuf)
	if err != nil {
		return nil, &PEMParseError{Err: err}
	}
	defer secure.Wipe(passphrase)

	signer, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, passphrase)
	if err != nil {
		return nil, &PEMParseError{Err: err}
	}
	return signer, nil
}

// AlgorithmFromPublicKey maps a parsed ssh.PublicKey to an Algorithm
// constant. Exported so sibling packages (authorized, session) can
// classify keys without duplicating the curve-inspection logic. Uses
// the x/crypto/ssh CryptoPublicKey interface when available (most keys
// produced by ParsePrivateKey implement it) to inspect the underlying
// crypto.PublicKey concrete type; falls back to the SSH public-key
// algorithm name for compatibility.
func AlgorithmFromPublicKey(pub ssh.PublicKey) (Algorithm, error) {
	if cpk, ok := pub.(ssh.CryptoPublicKey); ok {
		switch key := cpk.CryptoPublicKey().(type) {
		case ed25519.PublicKey:
			return AlgorithmEd25519, nil
		case *rsa.PublicKey:
			return AlgorithmRSA, nil
		case *ecdsa.PublicKey:
			switch key.Curve.Params().BitSize {
			case 256:
				return AlgorithmECDSAP256, nil
			case 384:
				return AlgorithmECDSAP384, nil
			case 521:
				return AlgorithmECDSAP521, nil
			default:
				return "", &UnsupportedAlgorithmError{Algorithm: "ecdsa-unknown-curve"}
			}
		}
	}
	// Fallback: inspect the SSH public-key algorithm name.
	switch pub.Type() {
	case ssh.KeyAlgoED25519:
		return AlgorithmEd25519, nil
	case ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		return AlgorithmRSA, nil
	case ssh.KeyAlgoECDSA256:
		return AlgorithmECDSAP256, nil
	case ssh.KeyAlgoECDSA384:
		return AlgorithmECDSAP384, nil
	case ssh.KeyAlgoECDSA521:
		return AlgorithmECDSAP521, nil
	}
	return "", &UnsupportedAlgorithmError{Algorithm: pub.Type()}
}

// DecodePEMBlock is a convenience used by tests and external tooling
// that need the raw PEM block without constructing a Key. It does NOT
// parse the key material — that path always goes through ParsePEM.
// Returns *PEMParseError on a malformed block.
func DecodePEMBlock(data []byte) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &PEMParseError{Err: errors.New("no PEM block found")}
	}
	return block, nil
}
