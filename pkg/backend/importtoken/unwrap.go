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

package importtoken

import (
	"context"
	"crypto/rsa"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Entry bundles a SealedRSAKey with the wrapping algorithm
// GetImportParameters issued it for. Every ImportBackend that needs to bind
// the two together -- so UnwrapKey can refuse key material wrapped under a
// different algorithm than the one the wrapping keypair was generated for
// (go-xkms#1342) -- uses *Entry as its Store's value type instead of a bare
// *SealedRSAKey.
type Entry struct {
	// Key is the sealed wrapping private key.
	Key *SealedRSAKey
	// Algorithm is the wrapping algorithm GetImportParameters generated
	// Key for.
	Algorithm backend.WrappingAlgorithm
}

// Destroy destroys the sealed wrapping key. Safe to call on a nil receiver.
// It is the natural destroy callback for an importtoken.Store[*Entry]:
// pass (*Entry).Destroy to New.
func (e *Entry) Destroy() {
	if e == nil {
		return
	}
	e.Key.Destroy()
}

// Unwrap decrypts wrapped -- key material that claims to have been wrapped
// with algorithm -- using e's sealed RSA private key. It is a thin
// convenience wrapper around the package-level Unwrap, supplying e.Key and
// e.Algorithm as the sealed key and the algorithm it was issued for.
func (e *Entry) Unwrap(ctx context.Context, algorithm backend.WrappingAlgorithm, wrapped []byte) ([]byte, error) {
	if e == nil {
		return nil, &UnavailableError{}
	}
	return Unwrap(ctx, e.Key, e.Algorithm, algorithm, wrapped)
}

// Unwrap opens sealed's enclave and decrypts wrapped using algorithm, the
// RSA-OAEP or hybrid RSA+AES-KWP unwrap logic every ImportBackend needs
// once it has resolved an import token to a wrapping keypair. It is the one
// place that logic lives; pkg/backend/software, pkg/keyprovider/symmetric
// and pkg/backend/azurekv all call it instead of each carrying its own copy
// of the SealedRSAKey.Use plus algorithm switch (go-xkms#1342).
//
// issued is the algorithm GetImportParameters recorded when it generated
// sealed -- the algorithm the caller's WrappingPublicKey was handed out
// under. algorithm is the algorithm wrapped claims to have been produced
// with. The two are compared before sealed's enclave is ever opened: a
// mismatch reports *AlgorithmMismatchError, so a caller cannot request an
// RSA-OAEP wrapping key and then present RSA-AES-KEY-WRAP ciphertext (or
// vice versa) against the same keypair.
//
// A SealedRSAKey.Use failure that decodes to a non-RSA private key is
// translated to an error wrapping backend.ErrInvalidKeyType, since every
// SealedRSAKey holds an RSA wrapping key by construction and a non-RSA
// enclave means the sealed payload was tampered with or corrupted. Every
// other failure -- from Use itself, or from the wrapping library -- is
// reported through the same *errs.Wrapped shape, so a caller cannot
// distinguish "malformed ciphertext" from "enclave already destroyed" from
// the error alone.
func Unwrap(ctx context.Context, sealed *SealedRSAKey, issued, algorithm backend.WrappingAlgorithm, wrapped []byte) ([]byte, error) {
	if issued != algorithm {
		return nil, &AlgorithmMismatchError{Issued: issued, Requested: algorithm}
	}

	var unwrapped []byte
	useErr := sealed.Use(ctx, func(privateKey *rsa.PrivateKey) error {
		var unwrapErr error
		switch algorithm {
		case backend.WrappingAlgorithmRSAES_OAEP_SHA_1, backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
			unwrapped, unwrapErr = wrapping.UnwrapRSAOAEP(wrapped, privateKey, algorithm)
		case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
			unwrapped, unwrapErr = wrapping.UnwrapRSAAES(wrapped, privateKey, algorithm)
		default:
			return &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: algorithm.String()}
		}
		return unwrapErr
	})
	if useErr != nil {
		// SealedRSAKey.Use reports a non-RSA enclave generically, since
		// every ImportBackend using it holds an RSA wrapping key by
		// construction; translate it to backend.ErrInvalidKeyType so
		// every caller's error contract is the same one the software
		// backend has always given callers checking
		// errors.Is(err, backend.ErrInvalidKeyType).
		var notRSA *NotRSAKeyError
		if errors.As(useErr, &notRSA) {
			return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "wrapping key is not RSA"}
		}
		return nil, &errs.Wrapped{Msg: "failed to unwrap key", Err: useErr}
	}

	return unwrapped, nil
}
