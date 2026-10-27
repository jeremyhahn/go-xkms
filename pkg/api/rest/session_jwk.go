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

package rest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/encoding/jwk"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// sessionSigningJWKAlg is the JWS algorithm of the session signing key:
// ECDSA P-256 with SHA-256, RFC 7518 §3.4 "ES256".
const sessionSigningJWKAlg = "ES256"

// SessionSigningKeyMissingError reports that the session signing key cannot
// be found: the XKMSService has no default backend, or the backend holds no
// key under the signing CN (the host REST surface has not provisioned it
// yet).
type SessionSigningKeyMissingError struct {
	CN      string
	Backend string
	Err     error
}

// Error implements the error interface.
func (e *SessionSigningKeyMissingError) Error() string {
	return "rest: session signing key \"" + e.CN + "\" not found on backend \"" +
		e.Backend + "\": " + e.Err.Error()
}

// Unwrap exposes the underlying lookup error for errors.As/errors.Is.
func (e *SessionSigningKeyMissingError) Unwrap() error { return e.Err }

// SessionSigningKeyExportError reports that the backend holds the session
// signing key but cannot hand out its public half.
type SessionSigningKeyExportError struct {
	CN      string
	Backend string
	Err     error
}

// Error implements the error interface.
func (e *SessionSigningKeyExportError) Error() string {
	return "rest: backend \"" + e.Backend + "\" cannot export the public key of session signing key \"" +
		e.CN + "\": " + e.Err.Error()
}

// Unwrap exposes the underlying backend error for errors.As/errors.Is.
func (e *SessionSigningKeyExportError) Unwrap() error { return e.Err }

// SessionSigningKeyTypeError reports that the key under the session signing
// CN is not an ECDSA P-256 key, the only key type an ES256 JWK
// (RFC 7518 §3.4) describes.
type SessionSigningKeyTypeError struct {
	CN string

	// KeyType names the key found: its Go type, and the curve for an EC key.
	KeyType string
}

// Error implements the error interface.
func (e *SessionSigningKeyTypeError) Error() string {
	return "rest: session signing key \"" + e.CN + "\" is " + e.KeyType +
		", not the ECDSA P-256 key an ES256 JWK requires"
}

// SessionSigningJWK returns the public JWK (RFC 7517 §4) of the key that
// signs the session tokens of the host REST surface NewHostServer builds
// from svc and opts. A composer publishes it in its own JWKS so that it
// verifies the tokens a go-xkms login returns; the private key never leaves
// the backend.
//
// opts must be the SessionOptions the surface was built with (nil selects
// the defaults): the JWK's "kid" (RFC 7517 §4.5) is the signing CN they
// resolve to, which is the kid BuildTokenIssuer stamps on every token's JWS
// header. The key is read, never generated: before the surface has
// provisioned it the call fails with *SessionSigningKeyMissingError.
func SessionSigningJWK(ctx context.Context, svc *xkms.XKMSService, opts *SessionOptions) (*jwk.JWK, error) {
	if svc == nil {
		return nil, &HostXKMSServiceRequiredError{}
	}
	if opts == nil {
		opts = &SessionOptions{}
	}
	cn := sessionSigningKeyCN(opts.SigningKeyCN)
	backendName := svc.DefaultBackendName()

	backend, err := svc.LookupDefaultBackend()
	if err != nil {
		return nil, &SessionSigningKeyMissingError{CN: cn, Backend: backendName, Err: err}
	}
	attrs := sessionSigningKeyAttributes(cn, backendName, backend.Type())
	if _, err := backend.GetKey(ctx, attrs); err != nil {
		return nil, &SessionSigningKeyMissingError{CN: cn, Backend: backendName, Err: err}
	}

	// The same Signer BuildTokenIssuer signs with, so the published key is
	// the one that verifies the tokens.
	signer, err := backend.Signer(ctx, attrs)
	if err != nil {
		return nil, &SessionSigningKeyExportError{CN: cn, Backend: backendName, Err: err}
	}
	pub := signer.Public()
	if pub == nil {
		return nil, &SessionSigningKeyExportError{CN: cn, Backend: backendName, Err: ErrSessionSigningKeyNoPublicKey}
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, &SessionSigningKeyTypeError{CN: cn, KeyType: fmt.Sprintf("%T", pub)}
	}
	if ecPub.Curve != elliptic.P256() {
		return nil, &SessionSigningKeyTypeError{CN: cn, KeyType: "ECDSA " + ecPub.Curve.Params().Name}
	}
	key, err := jwk.FromPublicKey(ecPub)
	if err != nil {
		return nil, &SessionSigningKeyTypeError{CN: cn, KeyType: "an invalid ECDSA P-256 point"}
	}
	key.Use = "sig"                // RFC 7517 §4.2
	key.Alg = sessionSigningJWKAlg // RFC 7517 §4.4, RFC 7518 §3.4
	key.Kid = cn                   // RFC 7517 §4.5: the kid BuildTokenIssuer stamps
	return key, nil
}
