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

// Package backend bridges the SSH key subsystem (pkg/ssh/keys) to the xkms
// crypto backends (software / tpm2 / pkcs11 / cloud KMS). It implements
// keys.BackendProvider over a types.KeyProvider resolved by backend ID, so an
// SSH key can be generated and signed on whichever backend the user selected
// in the xkey admin page — for hardware backends the private key never leaves
// the device.
package backend

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Resolver yields the crypto KeyProvider for a backend registry ID. It is
// implemented at the xkey layer (over xkmssdk.GetBackend) and at the xkmsd
// server layer (over *xkms.XKMSService) — both ultimately return a
// types.KeyProvider for the selected backend.
type Resolver interface {
	ResolveKeyProvider(ctx context.Context, backendID string) (types.KeyProvider, error)
}

// ResolverFunc adapts a plain function to the Resolver interface.
type ResolverFunc func(ctx context.Context, backendID string) (types.KeyProvider, error)

// ResolveKeyProvider calls f.
func (f ResolverFunc) ResolveKeyProvider(ctx context.Context, backendID string) (types.KeyProvider, error) {
	return f(ctx, backendID)
}

// Provider implements keys.BackendProvider by generating and signing on the
// xkms KeyProvider returned by its Resolver. It is the production bridge used
// by the SSH SDK embedded client and the GUI/CLI services.
type Provider struct {
	resolve Resolver
}

// compile-time assertion that Provider satisfies the keys seam.
var _ keys.BackendProvider = (*Provider)(nil)

// New constructs a Provider backed by resolver. Returns ErrNilResolver when
// resolver is nil.
func New(resolver Resolver) (*Provider, error) {
	if resolver == nil {
		return nil, &NilInputError{Field: "resolver"}
	}
	return &Provider{resolve: resolver}, nil
}

// GenerateKey generates an SSH-algorithm key on backendID under keyID and
// returns a crypto.Signer for the freshly generated private key. The private
// key is created and retained by the backend; only the signer crosses back.
func (p *Provider) GenerateKey(ctx context.Context, backendID, keyID string, algo keys.Algorithm, rsaBits int) (crypto.Signer, error) {
	kp, err := p.resolve.ResolveKeyProvider(ctx, backendID)
	if err != nil {
		return nil, err
	}
	if kp == nil {
		return nil, &BackendNotFoundError{BackendID: backendID}
	}
	attrs, err := buildAttrs(keyID, algo, rsaBits, kp)
	if err != nil {
		return nil, err
	}
	if _, err := kp.GenerateKey(ctx, attrs); err != nil {
		return nil, &GenerateError{BackendID: backendID, KeyID: keyID, Err: err}
	}
	signer, err := kp.Signer(ctx, attrs)
	if err != nil {
		return nil, &SignerError{BackendID: backendID, KeyID: keyID, Err: err}
	}
	return signer, nil
}

// Signer resolves a crypto.Signer for an existing backend-backed key. algo is
// used to reconstruct the key attributes (curve / size) needed to locate it.
func (p *Provider) Signer(ctx context.Context, backendID, keyID string, algo keys.Algorithm) (crypto.Signer, error) {
	kp, err := p.resolve.ResolveKeyProvider(ctx, backendID)
	if err != nil {
		return nil, err
	}
	if kp == nil {
		return nil, &BackendNotFoundError{BackendID: backendID}
	}
	attrs, err := buildAttrs(keyID, algo, 0, kp)
	if err != nil {
		return nil, err
	}
	signer, err := kp.Signer(ctx, attrs)
	if err != nil {
		return nil, &SignerError{BackendID: backendID, KeyID: keyID, Err: err}
	}
	return signer, nil
}

// DeleteKey removes a backend-backed key's private material from backendID.
// It is exposed for the SDK delete path (the keys.Store only drops the
// envelope; the backend must drop the key).
func (p *Provider) DeleteKey(ctx context.Context, backendID, keyID string, algo keys.Algorithm) error {
	kp, err := p.resolve.ResolveKeyProvider(ctx, backendID)
	if err != nil {
		return err
	}
	if kp == nil {
		return &BackendNotFoundError{BackendID: backendID}
	}
	attrs, err := buildAttrs(keyID, algo, 0, kp)
	if err != nil {
		return err
	}
	if derr := kp.DeleteKey(ctx, attrs); derr != nil {
		return &DeleteError{BackendID: backendID, KeyID: keyID, Err: derr}
	}
	return nil
}

// buildAttrs translates an SSH algorithm into xkms key attributes for kp.
// The StoreType is taken from the provider's own type so the generated key is
// namespaced to the correct backend, mirroring buildKeyAttributes in
// pkg/xkms/servicer_key.go.
func buildAttrs(keyID string, algo keys.Algorithm, rsaBits int, kp types.KeyProvider) (*types.KeyAttributes, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		StoreType: types.ParseStoreType(string(kp.Type())),
		KeyType:   types.KeyTypeSigning,
	}

	switch algo {
	case keys.AlgorithmEd25519:
		attrs.KeyAlgorithm = x509.Ed25519
	case keys.AlgorithmRSA:
		attrs.KeyAlgorithm = x509.RSA
		size := rsaBits
		if size == 0 {
			size = types.RSAKeySize4096
		}
		attrs.RSAAttributes = &types.RSAAttributes{KeySize: size}
	case keys.AlgorithmECDSAP256:
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.ECCAttributes = &types.ECCAttributes{Curve: elliptic.P256()}
	case keys.AlgorithmECDSAP384:
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.ECCAttributes = &types.ECCAttributes{Curve: elliptic.P384()}
	case keys.AlgorithmECDSAP521:
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.ECCAttributes = &types.ECCAttributes{Curve: elliptic.P521()}
	default:
		return nil, &UnsupportedAlgorithmError{Algorithm: string(algo)}
	}
	return attrs, nil
}
