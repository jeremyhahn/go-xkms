// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

//go:build pkcs11

// Package yubikey provides a KeyProvider wrapper for YubiKey PIV tokens.
// YubiKey PIV requires CKU_SO (management key) authentication for key
// generation, unlike standard PKCS#11 tokens which generate keys under
// CKU_USER. This wrapper handles the SO login transition transparently,
// delegating all other operations to the underlying PKCS#11 backend.
package yubikey

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/miekg/pkcs11"
)

// Provider wraps a PKCS#11 Backend to handle YubiKey PIV-specific
// behavior. Key generation uses CKU_SO (management key) authentication
// because YubiKey PIV maps key generation to a management key operation.
// All other operations delegate directly to the inner PKCS#11 backend.
type Provider struct {
	inner *xkms.PKCS11Backend
}

// NewProvider creates a YubiKey KeyProvider wrapping the given PKCS#11 backend.
// The backend's Config must have SOPIN set to the YubiKey management key
// for key generation to succeed.
func NewProvider(backend *xkms.PKCS11Backend) *Provider {
	return &Provider{inner: backend}
}

// Type returns the backend type identifier.
func (p *Provider) Type() xkms.BackendType {
	return p.inner.Type()
}

// Capabilities returns the inner backend's capabilities.
func (p *Provider) Capabilities() xkms.Capabilities {
	return p.inner.Capabilities()
}

// GenerateKey generates a key on the YubiKey using CKU_SO authentication.
// YubiKey PIV requires the management key for key generation, which maps
// to CKU_SO in the PKCS#11 interface. After generation, the session is
// restored to CKU_USER for subsequent signing operations.
//
// Once the key is generated on the hardware, GetKey retrieves the standard
// PKCS#11 signer for the newly-created key.
func (p *Provider) GenerateKey(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.PrivateKey, error) {
	cfg := p.inner.Config()
	if cfg.SOPIN == "" {
		return p.inner.GenerateKey(ctx, attrs)
	}

	pool := p.inner.Pool()
	if pool == nil {
		return nil, &WrappedError{Msg: "yubikey", Err: xkms.ErrPKCS11BackendNotInitialized}
	}

	switch attrs.KeyAlgorithm {
	case x509.ECDSA:
		if err := p.generateECDSAOnDevice(pool, attrs, cfg.SOPIN, cfg.PIN); err != nil {
			return nil, err
		}
		// Key now exists on the YubiKey. Use the standard PKCS#11 path
		// to obtain a properly initialized signer bound to the hardware key.
		return p.inner.GetKey(ctx, attrs)

	default:
		return nil, &MessageError{Msg: fmt.Sprintf("yubikey: unsupported algorithm: %s", attrs.KeyAlgorithm)}
	}
}

// GetKey retrieves an existing key from the YubiKey.
func (p *Provider) GetKey(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.PrivateKey, error) {
	return p.inner.GetKey(ctx, attrs)
}

// DeleteKey removes a key from the YubiKey.
func (p *Provider) DeleteKey(ctx context.Context, attrs *xkms.KeyAttributes) error {
	return p.inner.DeleteKey(ctx, attrs)
}

// ListKeys returns all keys managed by the inner backend.
func (p *Provider) ListKeys(ctx context.Context) ([]*xkms.KeyAttributes, error) {
	return p.inner.ListKeys(ctx)
}

// Signer returns a crypto.Signer for the key identified by attrs.
func (p *Provider) Signer(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.Signer, error) {
	return p.inner.Signer(ctx, attrs)
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
func (p *Provider) Decrypter(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.Decrypter, error) {
	return p.inner.Decrypter(ctx, attrs)
}

// RotateKey delegates to the inner backend.
func (p *Provider) RotateKey(ctx context.Context, attrs *xkms.KeyAttributes) error {
	return p.inner.RotateKey(ctx, attrs)
}

// Close delegates to the inner backend.
func (p *Provider) Close() error {
	return p.inner.Close()
}

// ECDSA curve OIDs.
var curveToOID = map[elliptic.Curve]asn1.ObjectIdentifier{
	elliptic.P256(): {1, 2, 840, 10045, 3, 1, 7},
	elliptic.P384(): {1, 3, 132, 0, 34},
	elliptic.P521(): {1, 3, 132, 0, 35},
}

// generateECDSAOnDevice creates an ECDSA key pair on the YubiKey under
// CKU_SO authentication. The key pair is persisted on the token; the caller
// should use inner.GetKey to obtain a signer afterward.
func (p *Provider) generateECDSAOnDevice(pool *xkms.PKCS11SessionPool, attrs *xkms.KeyAttributes, soPin, userPin string) error {
	curve := elliptic.P256()
	if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
		curve = attrs.ECCAttributes.Curve
	}

	oid, ok := curveToOID[curve]
	if !ok {
		return &MessageError{Msg: fmt.Sprintf("yubikey: unsupported curve: %s", curve.Params().Name)}
	}

	encodedOID, err := asn1.Marshal(oid)
	if err != nil {
		return &WrappedError{Msg: "yubikey: marshal curve OID", Err: err}
	}

	id := []byte(attrs.CN)

	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, encodedOID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, id),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, id),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	return pool.WithSOSession(soPin, userPin, func(session pkcs11.SessionHandle) error {
		_, _, err := pool.Ctx().GenerateKeyPair(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
			pubTemplate,
			privTemplate,
		)
		return err
	})
}

// Compile-time interface check.
var _ xkms.KeyProvider = (*Provider)(nil)
